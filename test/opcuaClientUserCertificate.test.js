const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const Module = require("node:module");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const ENDPOINT = "opc.tcp://localhost:4840";

// Loads the client node with the OPC UA library stubbed and returns a handle to
// drive it. readCertificate/readPrivateKeyPEM read the real files, like the
// real node-opcua-crypto does, so a missing file throws ENOENT.
function createClientNode(endpointConfig) {
  const clients = [];
  const sessionIdentities = [];
  const statuses = [];
  const sent = [];
  const handlers = {};

  const certificateManager = {
    async initialize() {},
    trustedFolder: "trusted",
    rejectedFolder: "rejected",
    crlFolder: "crl",
    issuersCertFolder: "issuers",
    issuersCrlFolder: "issuers-crl"
  };

  class MockClient extends EventEmitter {
    constructor() {
      super();
      this.clientCertificateManager = certificateManager;
    }
    async connect() {}
    async createSession(identity) {
      sessionIdentities.push(identity);
      return {
        sessionId: "active",
        close(callback) {
          if (callback) callback();
          return Promise.resolve();
        }
      };
    }
    disconnect(callback) {
      if (callback) callback();
      return Promise.resolve();
    }
  }

  const opcua = {
    AttributeIds: {},
    DataType: { Null: 0, NodeId: 17 },
    MessageSecurityMode: { None: 1 },
    OPCUAClient: {
      create() {
        const client = new MockClient();
        clients.push(client);
        return client;
      }
    },
    SecurityPolicy: { None: "None" },
    TimestampsToReturn: {},
    UserTokenType: { Anonymous: 0, Certificate: 2, UserName: 1 }
  };

  const identity = (value) => value;
  const chalk = new Proxy(identity, { get: () => identity });
  const stubs = {
    "async": { queue: function () { return { push() {} }; } },
    "chalk": chalk,
    "flatted": { stringify: JSON.stringify },
    "lodash.clonedeep": (value) => value,
    "node-opcua": opcua,
    "node-opcua-client-crawler": { NodeCrawler: class {} },
    "node-opcua-crypto": {
      readCertificate: (file) => fs.readFileSync(file),
      readPrivateKeyPEM: (file) => fs.readFileSync(file, "utf8")
    },
    "node-opcua-file-transfer": {},
    "./opcua-basics": {
      calc_milliseconds_by_time_and_unit: () => 300000,
      get_node_status: (status) => ({ fill: "green", shape: "dot", status })
    },
    "./utils": { createClientCertificateManager: () => certificateManager }
  };

  const originalLoad = Module._load;
  Module._load = function (request, parent, isMain) {
    if (Object.hasOwn(stubs, request)) {
      return stubs[request];
    }
    return originalLoad.call(this, request, parent, isMain);
  };

  let ClientNode;
  const modulePath = require.resolve("../opcua/102-opcuaclient");
  delete require.cache[modulePath];
  try {
    require(modulePath)({
      nodes: {
        createNode(node) {
          Object.assign(node, {
            debug() {},
            error() {},
            on(event, handler) { handlers[event] = handler; },
            send(msg) { sent.push(msg); },
            status(status) { statuses.push(status); },
            warn() {}
          });
        },
        getNode() {
          return {
            endpoint: ENDPOINT,
            login: false,
            none: false,
            securityMode: "None",
            securityPolicy: "None",
            ...endpointConfig
          };
        },
        registerType(name, constructor) {
          if (name === "OpcUa-Client") ClientNode = constructor;
        }
      },
      settings: { verbose: false }
    });
  } finally {
    Module._load = originalLoad;
    delete require.cache[modulePath];
  }

  const unhandled = [];
  const onUnhandled = (reason) => unhandled.push(reason);
  process.on("unhandledRejection", onUnhandled);

  const node = new ClientNode({
    action: "read",
    endpoint: "endpoint",
    keepsessionalive: false,
    name: "client",
    time: 1,
    timeUnit: "s"
  });

  return {
    node,
    sessionIdentities,
    statuses,
    sent,
    unhandled,
    reconnect(OpcUaEndpoint) {
      handlers.input({ action: "reconnect", OpcUaEndpoint });
    },
    // Output 2 messages that carry an error
    errors() {
      return sent.filter((m) => Array.isArray(m) && m[1] && m[1].error).map((m) => m[1].error);
    },
    async settle() {
      for (let i = 0; i < 10; i++) {
        await new Promise((resolve) => setImmediate(resolve));
      }
    },
    async close() {
      process.removeListener("unhandledRejection", onUnhandled);
      await new Promise((resolve) => handlers.close(resolve));
    }
  };
}

function tempDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "opcua-usercert-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function writeFiles(dir, name, certificate, key) {
  const certFile = path.join(dir, name + ".pem");
  const keyFile = path.join(dir, name + ".key");
  fs.writeFileSync(certFile, certificate);
  fs.writeFileSync(keyFile, key);
  return { certFile, keyFile };
}

test("a missing user certificate file is reported and does not connect or throw", async (t) => {
  const dir = tempDir(t);
  const { keyFile } = writeFiles(dir, "present", "cert", "key");
  const missingCert = path.join(dir, "missing.pem");
  const client = createClientNode({ usercert: true, userCertificate: missingCert, userPrivatekey: keyFile });
  await client.settle();
  t.after(() => client.close());

  assert.equal(client.sessionIdentities.length, 0, "must not connect without a usable certificate");
  assert.deepEqual(client.unhandled, [], "must not leave an unhandled rejection");
  assert.match(client.statuses.at(-1).text, /invalid certificate/);
  assert.ok(client.errors().some((e) => e.includes("User certificate file not found")), "error must be sent on output 2");
});

test("a missing user private key file is reported and does not connect or throw", async (t) => {
  const dir = tempDir(t);
  const { certFile } = writeFiles(dir, "present", "cert", "key");
  const missingKey = path.join(dir, "missing.key");
  const client = createClientNode({ usercert: true, userCertificate: certFile, userPrivatekey: missingKey });
  await client.settle();
  t.after(() => client.close());

  assert.equal(client.sessionIdentities.length, 0);
  assert.deepEqual(client.unhandled, []);
  assert.match(client.statuses.at(-1).text, /invalid certificate/);
  assert.ok(client.errors().some((e) => e.includes("User private key file not found")));
});

test("empty certificate paths are reported and do not throw", async (t) => {
  const client = createClientNode({ usercert: true, userCertificate: "", userPrivatekey: "" });
  await client.settle();
  t.after(() => client.close());

  assert.equal(client.sessionIdentities.length, 0);
  assert.deepEqual(client.unhandled, []);
  assert.match(client.statuses.at(-1).text, /invalid certificate/);
});

test("an unreadable certificate file is reported and does not throw", async (t) => {
  const dir = tempDir(t);
  // A directory exists but cannot be read as a file
  const { keyFile } = writeFiles(dir, "present", "cert", "key");
  const client = createClientNode({ usercert: true, userCertificate: dir, userPrivatekey: keyFile });
  await client.settle();
  t.after(() => client.close());

  assert.equal(client.sessionIdentities.length, 0);
  assert.deepEqual(client.unhandled, []);
  assert.match(client.statuses.at(-1).text, /invalid certificate/);
});

test("the node connects with the user certificate and key when the files exist", async (t) => {
  const dir = tempDir(t);
  const { certFile, keyFile } = writeFiles(dir, "client", "CERT-A", "KEY-A");
  const client = createClientNode({ usercert: true, userCertificate: certFile, userPrivatekey: keyFile });
  await client.settle();
  t.after(() => client.close());

  assert.equal(client.sessionIdentities.length, 1);
  const identity = client.sessionIdentities[0];
  assert.equal(identity.type, 2, "UserTokenType.Certificate");
  assert.equal(identity.certificateData.toString(), "CERT-A");
  assert.equal(identity.privateKey, "KEY-A");
});

test("files written after deploy are used on reconnect, without redeploying", async (t) => {
  const dir = tempDir(t);
  const certFile = path.join(dir, "client.pem");
  const keyFile = path.join(dir, "client.key");
  const client = createClientNode({ usercert: true, userCertificate: certFile, userPrivatekey: keyFile });
  await client.settle();
  t.after(() => client.close());
  assert.equal(client.sessionIdentities.length, 0, "no files yet, so no session");

  fs.writeFileSync(certFile, "CERT-A");
  fs.writeFileSync(keyFile, "KEY-A");
  client.reconnect({ endpoint: ENDPOINT, securityMode: "None", securityPolicy: "None", usercert: true });
  await client.settle();

  assert.equal(client.sessionIdentities.length, 1);
  assert.equal(client.sessionIdentities[0].certificateData.toString(), "CERT-A");

  // Replace the contents under the same names and reconnect again
  fs.writeFileSync(certFile, "CERT-B");
  client.reconnect({ endpoint: ENDPOINT, securityMode: "None", securityPolicy: "None", usercert: true });
  await client.settle();

  assert.equal(client.sessionIdentities.length, 2);
  assert.equal(client.sessionIdentities[1].certificateData.toString(), "CERT-B");
  assert.deepEqual(client.unhandled, []);
});

test("paths in msg.OpcUaEndpoint override the configured ones and omitted paths fall back", async (t) => {
  const dir = tempDir(t);
  const configured = writeFiles(dir, "configured", "CERT-CONFIGURED", "KEY-CONFIGURED");
  const override = writeFiles(dir, "override", "CERT-OVERRIDE", "KEY-OVERRIDE");
  const client = createClientNode({ usercert: true, userCertificate: configured.certFile, userPrivatekey: configured.keyFile });
  await client.settle();
  t.after(() => client.close());
  assert.equal(client.sessionIdentities.at(-1).certificateData.toString(), "CERT-CONFIGURED");

  client.reconnect({
    endpoint: ENDPOINT, securityMode: "None", securityPolicy: "None", usercert: true,
    userCertificate: override.certFile, userPrivatekey: override.keyFile
  });
  await client.settle();
  assert.equal(client.sessionIdentities.at(-1).certificateData.toString(), "CERT-OVERRIDE");
  assert.equal(client.sessionIdentities.at(-1).privateKey, "KEY-OVERRIDE");

  // No paths in the message: back to the configured files, not the previous override
  client.reconnect({ endpoint: ENDPOINT, securityMode: "None", securityPolicy: "None", usercert: true });
  await client.settle();
  assert.equal(client.sessionIdentities.at(-1).certificateData.toString(), "CERT-CONFIGURED");
  assert.deepEqual(client.unhandled, []);
});

test("a reconnect asking for a user certificate with missing files is reported and does not throw", async (t) => {
  const dir = tempDir(t);
  const client = createClientNode({ usercert: false, userCertificate: path.join(dir, "client.pem"), userPrivatekey: path.join(dir, "client.key") });
  await client.settle();
  t.after(() => client.close());
  assert.equal(client.sessionIdentities.length, 1, "usercert off: connects without a user certificate");

  client.reconnect({ endpoint: ENDPOINT, securityMode: "None", securityPolicy: "None", usercert: true });
  await client.settle();

  assert.equal(client.sessionIdentities.length, 1, "must not connect, and must not fall back to anonymous");
  assert.deepEqual(client.unhandled, []);
  assert.match(client.statuses.at(-1).text, /invalid certificate/);
});
