import test from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import { readFile } from 'node:fs/promises';

// Browser E2E keeps ignoreHTTPSErrors for the local test certificate, so chain and hostname
// verification are covered here against the acceptance host's CA-issued certificate.
const descriptorPath = process.env.DARKVAULT_ACCEPTANCE;
if (process.env.DARKVAULT_ACCEPTANCE_REQUIRED && !descriptorPath) throw new Error('DARKVAULT_ACCEPTANCE_REQUIRED is set without DARKVAULT_ACCEPTANCE');

function connect(options) {
    return new Promise((resolve, reject) => {
        const socket = tls.connect({ ...options, rejectUnauthorized: true }, () => { socket.end(); resolve(socket.getPeerCertificate()); });
        socket.on('error', reject);
    });
}

test('Admin endpoint certificate validates against a trusted CA and its hostname', { skip: !descriptorPath }, async () => {
    const descriptor = JSON.parse(await readFile(descriptorPath, 'utf8'));
    const { hostname, port } = new URL(descriptor.url);
    const ca = await readFile(descriptor.ca, 'utf8');
    // Node checks the certificate against servername or host; an IP host must not be sent as SNI.
    const certificate = await connect({ host: hostname, port: Number(port), ca });
    assert.ok(certificate.subject.CN === 'localhost' && certificate.issuer.CN !== certificate.subject.CN, 'The server certificate must be CA-issued');
    await assert.rejects(connect({ host: hostname, port: Number(port) }), /self-signed|unable to verify|UNABLE_TO_VERIFY|SELF_SIGNED/i);
    await assert.rejects(connect({ host: hostname, port: Number(port), servername: 'vault.example.com', ca }), /altnames|Hostname|ERR_TLS_CERT_ALTNAME_INVALID/i);
});
