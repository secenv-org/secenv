# secenvs: The Designer's Brief

## 1. Introduction & The Name

**secenvs** (Secure Environment) is the "Breeze" of secret management. It is a CLI tool and TypeScript SDK that
allows developers to encrypt their environment variables locally, making it 100% safe to commit sensitive
secrets (like API keys and database URLs) directly into Git.

## 2. Why We Exist (The Problem)

Most secret management tools (SOPS, HashiCorp Vault, Infisical) fail solo developers by introducing a massive
"Managerial Layer." They require registering projects, managing cloud accounts, creating project-specific
passwords, or running complex wrapper commands.

Because of this immense friction, solo developers simply don't use them. Our real competitors are:

1. Putting `export OPENAI_API_KEY=sk-proj-...` in `.zshrc` (horrifying but works).
2. Unencrypted `.env` files lying around (zero friction, high risk).
3. "I'll just remember it."

Developers often won't adopt a security tool until they commit a secret and panic, or lose their secrets when
switching laptops. **Our mission is to show them the fire, then hand them the extinguisher—before they get
burned.** We want to fix the problem _before_ the pain.

## 3. The Founder's Vision: The "Breeze" Philosophy

The core vision is simple: **Security without the ceremony. Git-safe secrets without the overhead.**

- **Identity over Passwords:** You don't manage passwords per project. You manage _Trust_ using your local
  identity (like an SSH key).
- **Single Source of Truth:** No extra config files (`secenvs.yaml`). Your `.env.enc` file is both your schema
  and your storage.
- **Zero Wrapper Dependency:** Instead of complex start commands, TypeScript apps just
  `import { env } from "secenvs"`. It decrypts exactly what it needs, exactly when it needs it.

**The Positioning Statement:** _"SOPS is for DevOps teams. secenvs is for solo TypeScript developers who want
Git-safe secrets without the ceremony."_

## 4. The Impact & The "Unfair Advantage"

We are building the ONLY tool that works identically everywhere:

- On your laptop.
- On your server.
- In your CI/CD pipelines.

By making the "right way" as frictionless as the "wrong way," we are bringing professional, secure secret
management to independent developers, indie hackers, and small teams. No more accidentally leaked Stripe keys
on GitHub. No more spending an hour setting up a new project's `.env` file just to start coding.

## 5. Tone & Messaging for the Landing Page

- **Direct & Brutally Honest**: Don't shy away from calling out developers' bad practices (like committing
  unencrypted `.env` files or hardcoding strings).
- **Lightweight & Breathable**: The internal philosophy is called the "Breeze" for a reason. The tool feels
  effortless to use. The design should reflect that—uncluttered, fast, highly modern, and magical.
- **Developer-Centric**: We are talking directly to solo TypeScript developers. Show them the "Before" (the
  pain of losing secrets or risking exposure) and the "After" (the magic 90-second setup).

## 6. Key Features to Highlight visually

- **Zero Wrapper DX:** Show how simple it is: `import { env } from "secenvs"`.
- **Selective Encryption:** Show a file where non-sensitive configs (like `PORT=3000`) stay readable
  plaintext, while sensitive API keys are encrypted on the same file.
- **Risk-Free Git Commits:** Illustrate pushing your `.env.enc` to public repositories with zero fear.
- **The "Doctor":** We have a built-in `secenvs doctor` command that acts as a health check to make sure the
  developer is set up correctly.

## 7. The Design Challenge

We are asking people to change an established, deeply ingrained workflow (the ubiquitous `.env` file). The
landing page needs to look incredibly premium and make adoption feel absolutely effortless. The design must
visually contrast the "managerial hell" of enterprise secret tools against the sleek, instant gratification of
`secenvs`.
