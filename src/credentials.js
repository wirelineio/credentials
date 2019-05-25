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
 * @param {Buffer} publicKey
 * @param {Buffer} signature
 */
function createProof(publicKey, signature) {
  return {
    type: cipher,
    created: new Date().toISOString(),
    creator: publicKey.toString('hex'),

    // https://w3c.github.io/vc-data-model/#json-web-token
    // TODO(burdon): Document why not using jws (https://tools.ietf.org/html/rfc7515)
    signature: signature.toString('hex')
  };
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
  return bufferFrom(canonicalStringify(json)).toString();
}

export function parseToken(token) {
  return JSON.parse(bufferFrom(token));
}

/**
 * Creates a verifiable credential.
 * https://w3c.github.io/vc-data-model/#credentials
 * https://w3c.github.io/vc-data-model/#example-1-a-simple-example-of-a-verifiable-credential
 *
 * @param keyPair
 * @param properties
 * @param claim
 */
export function createCredential(keyPair, properties, claim) {
  const credential = { ...properties, credentialSubject: claim };

  // TODO(burdon): Check/validate @context?
  credential.type = concatUnique(properties.type, 'VerifiableCredential');

  const message = bufferFrom(canonicalStringify(credential));
  const proof = createProof(keyPair.publicKey, crypto.sign(message, keyPair.secretKey));

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
  const { proof } = credential;

  // TODO(burdon): Additional well-formed checks.
  if (publicKey.toString('hex') !== proof.creator) {
    return false;
  }

  const message = Object.assign({}, credential);
  delete message.proof;

  return crypto.verify(bufferFrom(canonicalStringify(message)), proof.signature, publicKey);
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

  // TODO(burdon): Check/validate @context.
  presentation.type = concatUnique(presentation.type, 'VerifiablePresentation');

  const message = bufferFrom(canonicalStringify(presentation));
  const proof = createProof(keyPair.publicKey, crypto.sign(message, keyPair.secretKey));

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
  const { proof } = presentation;

  // TODO(burdon): Additional well-formed checks.
  if (publicKey.toString('hex') !== proof.creator) {
    return false;
  }

  const message = Object.assign({}, presentation);
  delete message.proof;

  return crypto.verify(bufferFrom(canonicalStringify(message)), proof.signature, publicKey);
}
