# TFTPD
This is a simple TFTP (Trivial File Transfer Protocol) server implementation in C of RFC 1350, RFC 2348 TFTP server supporting upto 3 concurrent sessions.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Building the Server](#building-the-server)
  - [Running the Server](#running-the-server)
- [Usage](#usage)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)

## Introduction

TFTP is a lightweight file transfer protocol often used for transferring files between devices in a local network. This project provides a TFTP server that allows users to read and write files.

## Features

- Basic TFTP protocol support.
- Read and write operations.
- Error handling for common TFTP errors.

## Getting Started

### Prerequisites

Before building and running the server, make sure you have the following installed:

- C compiler (e.g., GCC)
- Make build tool

### Building the Server

Clone the repository and navigate to the project directory:

```bash
git clone https://github.com/your-username/tftp-server.git
cd tftp-server
