# XmlSign

Cet outil est un démonstrateur pour la signature de fichier XML.
Il prend en entrée un fichier XML, et dump en sortie un fichier XML signé.

Il utilise un certificat PKCS#12 pour signer le XML.
Le mot de passe est passé en ligne de commande (unsecure) ou en variable d'environnement.

## génération du certificat

### openSSL

Certificat autosigné:
```
openssl req -x509 -sha256 -nodes -days 730 -newkey rsa:2048 -keyout mycert.key -out mycert.pem
openssl pkcs12 -export -out mycert.p12 -inkey mycert.key -in mycert.pem
```

### makecert

# XmlValidateSignature

Cet outil vérifie une signature. Il est requis contrairement à XmlSign que le certificat utilisé pour la signature ne soit PAS autosigné.
C'est une contrainte/limitation de https://github.com/egelke/xades/blob/master/XadesLib/XadesVerifier.cs

