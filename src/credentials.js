//
// Copyright 2019 Wireline, Inc.
//

import Ajv from 'ajv';
import bufferFrom from 'buffer-from';
import canonicalStringify from 'canonical-json';
import crypto from 'hypercore-crypto';

import CredentialSchema from './schema/credential.json';
import PresentationSchema from './schema/presentation.json';

const cipher = 'ed25519';

/** Add unique item to list. */
function concatUnique(items = [], item) {
  return [item].concat((items.length ? items : [item]).filter(t => t !== item));
}

/**
 * Creates a standard proof object.
 * https://w3c.github.io/vc-data-model/#proofs-signatures
 *
 * @param {Buffer} keyPair
 * @param {Buffer} obj
 */
function createProof(keyPair, obj) {

  return {
    type: cipher,
    created: new Date().toISOString(),
    creator: keyPair.publicKey.toString('hex'),

    // TODO(burdon): nonce. domain for presentation?

    // https://w3c.github.io/vc-data-model/#json-web-token
    // TODO(burdon): Document why we are not using jws (https://tools.ietf.org/html/rfc7515)
    signature: crypto.sign(bufferFrom(canonicalStringify(obj)), keyPair.secretKey).toString('hex')
  };
}

/**
 * Verify the proof matches the credential/presentation.
 *
 * @param publicKey
 * @param obj
 * @param proof
 * @return {boolean}
 */
function verifyProof(publicKey, obj, proof) {

  // TODO(burdon): Additional well-formed checks.
  if (publicKey.toString('hex') !== proof.creator) {
    return false;
  }

  return crypto.verify(bufferFrom(canonicalStringify(obj)), bufferFrom(proof.signature, 'hex'), publicKey);
}

//
// JSON Schema (http://json-schema.org)
//

const ajv = new Ajv();

const validateCredentialSchema = ajv.compile(CredentialSchema);
const validatePresentationSchema = ajv.compile(PresentationSchema);

export function validateCredential(credential) {
  const valid = validateCredentialSchema(credential);
  return valid ? { ok: true } : { errors: validateCredentialSchema.errors };
}

export function validatePresentation(presentation) {
  const valid = validatePresentationSchema(presentation);
  return valid ? { ok: true } : { errors: validatePresentationSchema.errors };
}

//
// Serialization
//

export function toToken(json) {
  return bufferFrom(canonicalStringify(json)).toString('hex');
}

export function parseToken(token) {
  return JSON.parse(bufferFrom(token, 'hex'));
}

/**
 * Creates a verifiable credential.
 * https://w3c.github.io/vc-data-model/#credentials
 * https://w3c.github.io/vc-data-model/#example-1-a-simple-example-of-a-verifiable-credential
 *
 * @param keyPair
 * @param properties
 * @param subject
 */
export function createCredential(keyPair, properties, subject) {
  const credential = { ...properties, credentialSubject: subject };

  // TODO(burdon): Use avj to augment object.
  credential['@context'] = concatUnique(credential['@context'], 'https://www.w3.org/2018/credentials/v1');
  credential.type = concatUnique(properties.type, 'VerifiableCredential');

  const proof = createProof(keyPair, credential);

  return { ...credential, proof };
}

/**
 * Verifies the credential.
 *
 * @param {Buffer} publicKey
 * @param credential
 * @return {boolean}
 */
export function verifyCredential(publicKey, credential) {
  if (!validateCredential(credential)) {
    return false;
  }

  const { proof } = credential;
  const obj = Object.assign({}, credential);
  delete obj.proof;

  return verifyProof(publicKey, obj, proof);
}

/**
 * Creates a verifiable presentation.
 * https://w3c.github.io/vc-data-model/#presentations
 * https://w3c.github.io/vc-data-model/#example-2-a-simple-example-of-a-verifiable-presentation
 *
 * @param keyPair
 * @param properties
 * @param credential
 */
export function createPresentation(keyPair, properties, credential) {
  const presentation = { ...properties, verifiableCredential: credential };

  // TODO(burdon): Use avj to augment object.
  presentation['@context'] = concatUnique(presentation['@context'], 'https://www.w3.org/2018/credentials/v1');
  presentation.type = concatUnique(presentation.type, 'VerifiablePresentation');

  const proof = createProof(keyPair, presentation);

  return { ...presentation, proof };
}

/**
 * Verifies the credential.
 *
 * @param {Buffer} publicKey
 * @param presentation
 * @return {boolean}
 */
export function verifyPresentation(publicKey, presentation) {
  if (!validatePresentation(presentation)) {
    return false;
  }

  const { proof } = presentation;
  const obj = Object.assign({}, presentation);
  delete obj.proof;

  return verifyProof(publicKey, obj, proof);
}
