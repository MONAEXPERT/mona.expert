import assert from "node:assert/strict";
import test from "node:test";
import { EventEmitter } from "node:events";
import {
  subscribe,
  broadcast,
  subscriberCount,
  clearSubscribers,
} from "../src/event-bus.js";

test("subscriberCount starts at 0", () => {
  clearSubscribers();
  assert.equal(subscriberCount(), 0);
});

test("subscribe adds a subscriber", () => {
  clearSubscribers();
  const res = new EventEmitter();
  res.write = () => true;

  const unsubscribe = subscribe(res);
  assert.equal(subscriberCount(), 1);

  unsubscribe();
  assert.equal(subscriberCount(), 0);
});

test("broadcast sends event to all subscribers", () => {
  clearSubscribers();
  const received = [];

  const res1 = new EventEmitter();
  res1.write = (msg) => {
    received.push({ sub: 1, msg });
    return true;
  };

  const res2 = new EventEmitter();
  res2.write = (msg) => {
    received.push({ sub: 2, msg });
    return true;
  };

  subscribe(res1);
  subscribe(res2);
  broadcast("test", { hello: "world" });

  assert.equal(received.length, 2);
  for (const r of received) {
    assert.ok(r.msg.startsWith("event: test\n"));
    assert.ok(r.msg.includes('"hello":"world"'));
  }
});

test("broadcast removes failing subscribers silently", () => {
  clearSubscribers();
  const errors = [];

  const good = new EventEmitter();
  good.write = (msg) => true;

  const bad = new EventEmitter();
  bad.write = () => {
    throw new Error("write failed");
  };

  subscribe(bad);
  subscribe(good);

  // Should not throw — full coverage of try/catch in broadcast
  broadcast("event", {});
  assert.equal(subscriberCount(), 1); // bad was removed
});

test("broadcast handles type and payload correctly", () => {
  clearSubscribers();
  const msgs = [];

  const res = new EventEmitter();
  res.write = (msg) => {
    msgs.push(msg);
    return true;
  };

  subscribe(res);
  broadcast("status", { ok: true });

  assert.ok(msgs[0].includes("event: status\n"));
  assert.ok(msgs[0].includes('"ok":true'));
});

test("unsubscribe removes correct subscriber", () => {
  clearSubscribers();
  const res1 = new EventEmitter();
  res1.write = () => true;
  const res2 = new EventEmitter();
  res2.write = () => true;

  const unsub1 = subscribe(res1);
  subscribe(res2);

  assert.equal(subscriberCount(), 2);

  unsub1();
  assert.equal(subscriberCount(), 1);

  // Remaining subscriber still gets broadcasts
  const received = [];
  const origWrite = res2.write;
  res2.write = (msg) => {
    received.push(msg);
    return true;
  };

  broadcast("ping", {});
  assert.equal(received.length, 1);
});
