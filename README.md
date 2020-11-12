# ProtonMail Security Analysis

[ProtonMail](https://protonmail.com/) is an email service providing end-to-end encryption for emails between ProtonMail users, as well as between ProtonMail users and other [Pretty Good Privacy (PGP)](https://www.openpgp.org/) compatible senders and receivers.

The goal of this repository is to analyse the claimed security of ProtonMail, in particular, the encryption and management of the users' private keys.

## Contents

### Simulation

The [src/](src) directory in this repository contains a Python script that simulates the encryption of a PGP private key as done by ProtonMail.

The goal is that, given the same inputs (unencrypted private key, user password, salts, initialisation vectors), the simulation produces the exact same encrypted private key as ProtonMail.

### Annotated web client

The associated [weibeld/WebClient](https://github.com/weibeld/WebClient) repository is a fork of the official web client of ProtonMail ([ProtonMail/WebClient](https://github.com/ProtonMail/WebClient)) and contains log outputs that allow to trace the execution of the web client.

Currently, mainly the account creation logic is traced, which contains the creation and encryption of the user's private key.

## ProtonMail accounts

Here's a list of currently active ProtonMail accounts that can be used for testing:

| Username   | Password |
|------------|:--------:|
| uhzgslvtph | ***      |
