# Verifiable Credentials

A simple library to create and validate verifiable credentials from the [Web3 spec](https://w3c.github.io/vc-data-model).

```bash
npm install @wirelineio/credentials
```

## Usage

To create and verify a verifiable credential:

```javascript
import { createCredential, verifyCredential } from '@wirelineio/credentials';

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

verifyCredential(issuerKeyPair.publicKey, issuedCredential);
```

To create and verify a verifiable presentation:

```javascript
import { createPresentation, verifyPresentation } from '@wirelineio/credentials';

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

verifyPresentation(presenterKeyPair.publicKey, presentedCredential);
```
