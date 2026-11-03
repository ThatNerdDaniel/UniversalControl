// Staged replacement of existing registry: configurable lifetime cap only; no owner-specific settings.
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import path from 'node:path';

const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const same = (a,b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a),Buffer.from(b));
const valid = (value, length=256) => typeof value === 'string' && value.length > 0 && value.length <= length;

export class PeerRegistry extends EventEmitter {
  constructor({ filename, ownerKey, initialize = false, clock = Date.now, maxEnrollmentMs = 300000 }) {
    super(); if (!path.isAbsolute(filename ?? '')) throw Error('Explicit registry filename required');
    if(!Number.isInteger(maxEnrollmentMs)||maxEnrollmentMs<1000||maxEnrollmentMs>900000)throw Error('Invalid enrollment lifetime policy');this.maxEnrollmentMs=maxEnrollmentMs;this.clock = clock;
    if (!initialize && !fs.existsSync(filename)) throw Error('Registry not bootstrapped');
    fs.mkdirSync(path.dirname(filename),{recursive:true}); this.db = new DatabaseSync(filename);
    try {
      this.db.exec('PRAGMA busy_timeout=1000');
      if (initialize) {
        if (!valid(ownerKey) || ownerKey.length < 32) throw Error('Explicit owner key required');
        this.db.exec('BEGIN IMMEDIATE; CREATE TABLE owner(keyhash TEXT NOT NULL); CREATE TABLE window(device TEXT PRIMARY KEY, fingerprint TEXT, tokenhash TEXT, expires INTEGER, used INTEGER); CREATE TABLE peer(device TEXT PRIMARY KEY,fingerprint TEXT UNIQUE,subject TEXT,client TEXT,state TEXT,request TEXT UNIQUE,expires INTEGER,scope TEXT)');
        this.db.prepare('INSERT INTO owner VALUES(?)').run(hash(ownerKey)); this.db.exec('COMMIT');
      } else this.db.prepare('SELECT keyhash FROM owner').get();
    } catch (e) { try { this.db.exec('ROLLBACK'); } catch {} this.db.close(); throw e; }
  }
  owner(key) { if (!valid(key) || !same(hash(key),this.db.prepare('SELECT keyhash FROM owner').get().keyhash)) throw Error('Owner authorization denied'); }
  open(ownerKey,{device,fingerprint,subject,client,ttl=60000}) {
    this.owner(ownerKey);
    if (!/^[A-Z0-9-]{1,64}$/.test(device) || !/^[a-f0-9]{64}$/.test(fingerprint) || !valid(subject) || !valid(client)
      || !Number.isInteger(ttl) || ttl < 1 || ttl > this.maxEnrollmentMs) throw Error('Invalid enrollment request');
    if (this.db.prepare('SELECT 1 FROM peer WHERE device=?').get(device)) throw Error('Known device requires explicit revoke/reset, never silent re-pairing');
    const token=crypto.randomBytes(32).toString('hex'), expires=this.clock()+ttl;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      if (this.db.prepare("SELECT 1 FROM peer WHERE state='pending' AND expires>?").get(this.clock())) throw Error('Pairing already pending');
      this.db.exec('DELETE FROM window');
      this.db.prepare('INSERT INTO window VALUES(?,?,?,?,0)').run(device,fingerprint,hash(token),expires);
      // Owner fixes the OAuth identity before the request; agent cannot select it.
      this.db.prepare("INSERT INTO peer VALUES(?,?,?,?,'invited',NULL,?,'whole_machine')").run(device,fingerprint,subject,client,expires);
      this.db.exec('COMMIT');
    } catch (e) { this.db.exec('ROLLBACK'); throw e; }
    return token;
  }
  request({device,fingerprint,token}) {
    if (!valid(token,128)) throw Error('Enrollment closed');
    const w=this.db.prepare('SELECT * FROM window WHERE device=?').get(device);
    if (!w || w.used || w.expires<=this.clock() || !same(w.tokenhash,hash(token)) || !same(w.fingerprint,fingerprint)) throw Error('Enrollment closed, expired or wrong authenticated device');
    const request=crypto.randomUUID();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const r=this.db.prepare('UPDATE window SET used=1 WHERE device=? AND used=0').run(device);
      if (r.changes!==1) throw Error('Enrollment already used');
      if(this.db.prepare("UPDATE peer SET state='pending',request=? WHERE device=? AND state='invited'").run(request,device).changes!==1)throw Error('Device is no longer invited');
      this.db.exec('COMMIT');
    } catch(e) { this.db.exec('ROLLBACK'); throw e; }
    const result={device,fingerprint,request,scope:'whole_machine'}; this.emit('pairing',result); return result;
  }
  decide(ownerKey,request,approve,identity) {
    this.owner(ownerKey); if(typeof approve!=='boolean') throw Error('Explicit decision required');
    const d=this.db.prepare('SELECT * FROM peer WHERE request=?').get(request);
    if (!d || d.state!=='pending' || d.expires<=this.clock()) throw Error('Pending pairing expired or already decided');
    const subject=identity?.subject??d.subject,client=identity?.client??d.client;
    if(!valid(subject)||!valid(client))throw Error('Exact owner/client binding required');
    if(this.db.prepare("UPDATE peer SET state=?,subject=?,client=? WHERE request=? AND state='pending' AND expires>?").run(approve?'approved':'denied',subject,client,request,this.clock()).changes!==1)throw Error('Pairing already decided or expired');
  }
  active(device,fingerprint) {
    const d=this.db.prepare('SELECT * FROM peer WHERE device=?').get(device);
    if (!d || d.state!=='approved' || !same(d.fingerprint,fingerprint)) throw Error('Unapproved, wrong or revoked device');
    return d;
  }
  record(device){return this.db.prepare('SELECT device,fingerprint,subject,client,state,request,expires,scope FROM peer WHERE device=?').get(device)??null;}
  resetUnapproved(ownerKey,device){
    this.owner(ownerKey);const d=this.record(device);
    if(!d||!['invited','pending'].includes(d.state)||d.state==='pending'&&d.expires>this.clock())throw Error('Only unopened or expired unapproved invitations may be reset');
    this.db.exec('BEGIN IMMEDIATE');try{this.db.prepare('DELETE FROM window WHERE device=?').run(device);this.db.prepare('DELETE FROM peer WHERE device=?').run(device);this.db.exec('COMMIT');}catch(e){this.db.exec('ROLLBACK');throw e;}
  }
  resumePending({device,fingerprint,token}){
    const d=this.record(device),w=this.db.prepare('SELECT * FROM window WHERE device=?').get(device);
    if(!d||d.state!=='pending'||d.expires<=this.clock()||!same(d.fingerprint,fingerprint)||!w||!valid(token,128)||!same(w.tokenhash,hash(token)))throw Error('No matching pending pairing');
    return {device,fingerprint,request:d.request,scope:d.scope};
  }
  grant(subject,client,device) {
    const d=this.db.prepare("SELECT * FROM peer WHERE device=? AND subject=? AND client=? AND state='approved'").get(device,subject,client);
    return d?{active:true,scope:d.scope,subject:d.subject,client:d.client,device:d.device}:null;
  }
  revoke(ownerKey,device) {
    this.owner(ownerKey);
    this.db.exec('BEGIN IMMEDIATE');try{
      if(this.db.prepare("UPDATE peer SET state='revoked' WHERE device=?").run(device).changes!==1)throw Error('Unknown device');
      this.db.prepare('UPDATE window SET used=1 WHERE device=?').run(device);this.db.exec('COMMIT');
    }catch(e){this.db.exec('ROLLBACK');throw e;}
    this.emit('revoked',device);
  }
  close(){if(!this.closed){this.closed=true;this.db.close();}}
}
