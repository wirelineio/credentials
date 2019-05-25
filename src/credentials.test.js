//
// Copyright 2019 Wireline, Inc.
//

import crypto from 'hypercore-crypto';

import {
  validateCredential,
  validatePresentation,
  createCredential,
  createPresentation,
  verifyCredential,
  verifyPresentation
} from './credentials';

import CredentialTest from './testing/test_credential.json';
import PresentationTest from './testing/test_presentation.json';

test('JSON schema', () => {

  expect(validateCredential(CredentialTest).errors).toBeFalsy();
  expect(validatePresentation(PresentationTest).errors).toBeFalsy();
});

test('basic encoding/decoding of credentials', () => {

  //
  // Issued Credential
  //

  const claim = {
    id: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
    degree: {
      type: 'BachelorDegree',
      name: 'Computer Science'
    }
  };

  const issuerMetadata = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://www.w3.org/2018/credentials/examples/v1'
    ],

    id: 'did:example:abfe13f712120431c276e12ecab',
    issuanceDate: new Date().toISOString()
  };

  const issuerKeyPair = crypto.keyPair();
  const issuedCredential = createCredential(issuerKeyPair, issuerMetadata, claim);
  console.log('Credential:', JSON.stringify(issuedCredential, null, 2));

  verifyCredential(issuerKeyPair.publicKey, issuedCredential);

  //
  // Presented Credential
  //

  const presenterMetadata = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://www.w3.org/2018/credentials/examples/v1'
    ],

    id: 'did:example:abfe13f712120431c276e12ecab',
    presentationDate: new Date().toISOString()
  };

  const presenterKeyPair = crypto.keyPair();
  const presentedCredential = createPresentation(presenterKeyPair, presenterMetadata, issuedCredential);
  console.log('Presentation:', JSON.stringify(presentedCredential, null, 2));

  verifyPresentation(presenterKeyPair.publicKey, presentedCredential);
});
