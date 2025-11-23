# EnvSync

🚀 Project Overview

EnvSync is a developer-focused CLI tool and backend service designed to securely manage, sync, and distribute .env files across devices and teams.
It ensures that API keys, secrets, tokens, and environment configurations are never lost, never shared insecurely, and never accidentally committed to GitHub.

The entire system uses end-to-end encryption, meaning the server cannot read or decrypt any environment variables. Only trusted devices with the correct keys can decrypt the data, ensuring maximum security.

EnvSync eliminates:

- manually copying .env files between machines
- insecure sharing via WhatsApp/Telegram
- version mismatches between teammates
- GitHub API rate-limit issues caused by missing env
- misconfigured staging/dev/prod environments

🌟 Problem EnvSync Solves

Every developer faces these issues:

❌ .env lost after system reset
❌ .env different on laptop vs PC
❌ teammate has old env → project fails
❌ sending secrets on insecure channels
❌ committing .env to GitHub by mistake
❌ maintaining multiple environment versions manually

EnvSync solves all of these in one command.

🎯 Key Features

🔐 1. End-to-End Encryption (Zero Knowledge)

All .env files are encrypted locally with AES-256-GCM.

Access keys are exchanged using RSA 4096-bit encryption.

Server stores only encrypted blobs — readable by nobody, not even admin.

Perfect for security-sensitive environments.

📦 2. Cross-Device Sync

Commands like:

- `envsync init` - Initialize a new project or device
- `envsync pull` - Pull the latest .env from the server
- `envsync push` - Push local .env changes to the server
- `envsync diff` - Show differences between local and remote .env

## Installation

### CLI

```bash
go build -o envsync
```

### Server

#### Option 1: Local PostgreSQL

```bash
# Set up PostgreSQL database
createdb envsync
psql envsync -c "CREATE USER envsync WITH PASSWORD 'password';"
psql envsync -c "GRANT ALL PRIVILEGES ON DATABASE envsync TO envsync;"

cd server
go run main.go
```

#### Option 2: Docker Compose (Recommended)

```bash
cd server
docker-compose up -d
```

This starts both PostgreSQL and the EnvSync server in containers.

## Usage

1. Initialize a project:

   ```bash
   envsync init
   ```

2. Edit your .env file

3. Push to server:

   ```bash
   envsync push
   ```

4. On another device, pull:

   ```bash
   envsync pull
   ```

5. Check differences:

   ```bash
   envsync diff
   ```

## API Endpoints

- `POST /projects/{project_id}/env` - Push encrypted .env data
- `GET /projects/{project_id}/env?device_id={device_id}` - Pull encrypted .env data

## Contributing

TODO: Add contributing guidelines

## License

See LICENSE file.
