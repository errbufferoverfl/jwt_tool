<h1 align="center">The JSON Web Token Toolkit [redux]</h1>

<div align="center">
</div>
<div align="center">
<strong>A toolkit for validating, forging and tampering with JSON Web Tokens (JWTs).</strong>
</div>
<div align="center">
A small dopamine rabbit hole.
</div>

<div align="center">
<h3>
<a href="https://gitlab.com/errbufferoverfl/jwt_tool/">Repository</a>
<span> | </span>
<a href="https://gitlab.com/errbufferoverfl/jwt_tool/-/wikis/introduction">Handbook</a>
<span> | </span>
<a href="#contributing">Contributing</a>
</h3>
</div>

<div align="center">
<sub>The little experiment that could.<br>Built with ❤︎ by
<a href="https://genericsocialmediapage.com/@errbufferoverfl">errbufferoverfl</a>.
</sub>
</div>

## Introduction

The JSON Web Token Toolkit [redux] is a suite designed to test the security and robustness of JSON Web Tokens (JWTs). This tool provides a range of functionalities aimed at validating tokens, testing for known exploits, scanning for misconfigurations, and much more.

The JWT Toolkit [redux] is made for penetration testers, CTF participants and developers alike, providing extensive tampering, signing, and verifying options to uncover potential weaknesses in web applications using JWTs.

Some of the key features of the JWT Toolkit [redux] include:

* Token Validity Checks: Verify the validity of JWTs to ensure they conform to standards and are properly structured.
* Exploit Testing: Test for several known vulnerabilities, including:
  * CVE-2015-2951: The alg=none signature-bypass vulnerability
  * CVE-2016-10555: The RS/HS256 public key mismatch vulnerability
  * CVE-2018-0114: Key injection vulnerability
  * CVE-2019-20933/CVE-2020-28637: Blank password vulnerability
  * CVE-2020-28042: Null signature vulnerability
* Misconfiguration Scanning: Identify and report on potential misconfigurations or weaknesses in JWT setups.
* Claim Fuzzing: Fuzz claim values to provoke unexpected behaviors and identify potential flaws.
* Secret/Key Validation: Test the validity of secrets, key files, public keys, and JWKS keys.
* Weak Key Identification: Use high-speed dictionary attacks to identify weak keys.
* Token Forgery: Forge new token headers and payloads, and create new signatures with keys or via attack methods.
* Timestamp Tampering: Manipulate timestamps to test the resilience of JWTs against time-based attacks.
* Key Generation and Reconstruction: Generate and reconstruct RSA and ECDSA keys, including from JWKS files.

## Table of contents

- [Introduction](#introduction)
- [Design Principles](#design-principles)
- [Installing](#installing)
- [Getting Started](#getting-started)
  - [Setup](#setup)
- [License](#license)

## Design Principles

* **Modularity and Separation of Concerns**
  * **Class Responsibilities:** Clear division of responsibilities among various classes (e.g., JWT, Header, Payload, SigningConfig), making each class handle a specific part of JWT handling.
  * **Reusable Components:** Designing classes and methods to be reusable and focused on single responsibilities.
* **Clarity, Readability, and Usability**
  * **Descriptive Names and Documentation:** Use of descriptive method names, comprehensive docstrings, and inline comments to make the codebase easy to understand and maintain.
  * **User-Friendly CLI:** Integration with Click for a command-line interface that enhances usability, allowing users to interact with the tool easily.
* **Flexibility and Extensibility**
  * **Configurable Components:** Introduction of configurable components like SigningConfig to allow flexibility in specifying signing algorithms and keys.
  * **Constants for Special Values:** Use of constants to represent special states, making the code more extensible and clear in its intentions.

## Installing

The [JWT Tool CLI guide](https://gitlab.com/errbufferoverfl/jwt_tool/-/wikis/jwt-tool-cli), has more information on installation, usage and exit codes.

The easiest way to install JWT Toolkit [redux] is through git:

```shell
git clone git@gitlab.com:errbufferoverfl/jwt_tool.git
```

## Getting Started

In the [Quickstart guide](https://gitlab.com/errbufferoverfl/jwt_tool/-/wikis/introduction/quickstart), you'll learn how to get started with JWT Tool [redux] from configuring the tool to running your first scan. It covers **configuration**, and **running** the tool.

The setup instructions below provide a high-level overview of the steps needed to setup JWT Toolkit [redux].

### Setup

#### 1. Installation

Install JWT Toolkit [redux] on your computer with the following command:

```shell
git clone git@gitlab.com:errbufferoverfl/jwt_tool.git
```

#### 2. Generate a Configuration File

_Coming soon._

#### 3. Run a Scan

_Coming soon._


## Contributing

Please submit patches to code or documentation as GitLab pull requests.

Contributions must be licensed under the GNU GPLv3. The contributor retains the copyright.

## License

The JSON Web Token Toolkit [redux] is released under GNU General Public License v3.0 or later.

See [LICENSE](LICENSE) for the full text.