# ATD Snyk Vuln Matrix 
## Kickstart `ATd` (Astro, TailwindCSS, daisyUI) adding Snyk for package security

#### Gated for CI/CD | Robust | Minimal Hassle

---

### 🦑 Why I needed this and you may as well.
`Environments` `Debian 13, FNM, Nushell (Linux) 0.112.0` `Debian 13, FNM, ZSH 5.1`
`Should work w/ NVM`

I  was looking around needing a way to render a site w/ dynamic content, and easy dev database hooks. I discovered Astro and thought to myself, "Self, it can't get much better than this."

Until I got `npm` in place and got site packages installed.

While `phenomenal`, the following components **can** contain some decently shitty vulnerabilities.


- [Astro](https://astro.build/) – Being a fast and content-focused framework.
- [TailwindCSS](https://tailwindcss.com/) – Utility-first CSS engine, no longer postcss bound.
- [DaisyUI](https://daisyui.com/) – Beautiful and customizable UI components, easy to skin and allow for TailwindCSS right along side.


The above provide awesome ability inside a simple, scalable project structure. A great starting point for me.

Hot damn though, the WARNS post  `npm install` can be alarming.</p> Even `npm install update` might make one itch a bit, albeit much better rn w/ only 5 vulns, none HIGH or CRIT.

With surprising realism (denial isn't just a river in Egypt), I knew that a vulnerability matrix was going to be essential with coping. Building on top of these components were going to be database connectors, auth pieces and the like and their dep chains. In this day and age of rapid bug discovery and vulnerability proof-of-concepting, the more I can pay attention easily, the better off I likely am.

This isn't as far as I'm thinking, for a production system. More for development environs. I included Snyk gating so it *could* be included in a CD/CI trip, but don't have a formalized thing like that in my world as of yet (i.e., I don't know if it'd work as is)

#### Snyk is our friend.

[Snyk User Doc](https://github.com/snyk/user-docs), Built them into my Obsidian vault in a doc specific directory. That documentation is why I could take a freak-out sorta idea, and make hay. Not gonna lie, a fair bit of this was more or less ripped from Snyk's documentation. Big debt. Bottom of this file is the link to `dashboarding`.

For the full me experience of local dev machine install, Snyk binaries are here;
    https://downloads.snyk.io/cli/stable/release.json
Per Snyk doc, binary executable versions need to be updated manually. Also per the docs, there are multiple ways to skin that cat, including pkg mgr files.

Remember that old cowsay!
```bash
__________________________
< Breathe, reflect, build. >
--------------------------
       \   ^__^
        \  (**)\_______
           (__)\       )\/\
            U  ||----w |
               ||     ||
```
Look at those eyes. What's that cow been smoking?

---

### 📦 Starting out


Go ahead and Git 🫣 this repository:

```bash
git clone https://github.com/lount-ops/vulnmatrix
cd vulnmatrix
```

### Install and update dependencies:

Create and activate a virtual env w/ what ever method you normally do so that `pip` is available.
```bash
pip install --upgrade pip
pip install nodeenv
nodeenv -p
```

Or using Nushell and `fnm`
```nu
fnm exec npx npm-check-updates -u; npm -i
```

With the node environment in place, `npx` and `npm` are now available for `ZSH` or `Bash`
```bash
npx npm-check-updates -u && npm i 
# non FNM laced
```

FWIW:
```
Local `venv` I built this in:
```bash
> python3 --version
Python 3.13.5    # uv for venv mgmt, use pip to install nodeenv
> node -v
v24.14.1  # fnm or nvm for alignment
> fnm
1.39.0   # cargo installable

```

```bash
npx npm audit fix
```

It's likely at this point, npm is complaining about needing someone to run an `audit fix` and there could be between one and... `/me rolls dice` 19 packages needing attention.

Runs as expected w/ `npm`
```zsh
npm run dev
```

Or `deno`
```zsh
deno run dev
```

The landing page should be the ATdS matrix.

To get newer data, run the `snyk harvest` script in the doc root:
```
./snyk-harvest.zsh
```

Then reload the index page.
### Under the Hood;

#### 🛠 Base️ Project Structure Breakdown

```
/                     # snyk-harvest script and .snyk-reports home, 
├── public/           # Static assets
├── src/
│   ├── assets/       # Assets Files
│   ├── components/   # Reusable components
│   ├── layouts/      # Layout files
|   ├── lib/          # load-vulns.mjs lives here
│   └── pages/        # Pages (routes), VulnMatrix.astro, vulns.json.js home
|   |        └── api/        # vulns.json.js home
│   └── styles/       # Style Files
├── astro.config.mjs  # Astro configuration
├── tailwind.config.js # TailwindCSS configuration
└── package.json

## All pathing can be adjustsed w/out hassle
```

### 🌱 Why use this scaffolding?

- No idea – My dad said I was a squid a long time ago. However; It (the Snyk/NPM vuln_matrix) seemed like a smart move on my part.
- Plus side? Ready to move in quickly with Tailwind, daisyUI & Snyk.
- Perfect base. Astro is really bitchin. With TailwindCSS and daisyUI rolled in, I saw it as a solid base for what I needed to get done. – It's possible you are taking a hard look at it as well - This way in dev, you can scale your project however you want with security in mind.

#### 🪝 Added Security Layers to Consider

Deno runtime for strictness, tho it's tweaky w/ Astro.
`npm run dev` gets replaced by: `deno run dev` (or `deno task dev`), leading to a shiny world.

[Deno]() installed via [Pacstall](), for the `'aptification'` of things.
[Astro Guide: Deploy > Deno](https://docs.astro.build/en/guides/deploy/deno/)
[Deno Examples: Build Astro w/ Deno](https://docs.deno.com/examples/astro_tutorial/)

## License

MIT — Feel free to use, modify, and share.

---
### Snyk Links:
- Building your first dashboard - https://docs.snyk.io/manage-risk/analytics/reports-tab/reporting-and-bi-integrations-snowflake-data-share/build-your-first-dashboard - I couldn't believe this when I found it. Thank you Snyk folks!
- debugging the CLI - https://docs.snyk.io/developer-tools/snyk-cli/debugging-the-snyk-cli  `snyk test --debug --log-level=trace` or:
```bash
     export SNYK_LOG_LEVEL=trace 
     snyk test --debug
```
 - snyk test - https://docs.snyk.io/developer-tools/snyk-cli/commands/test Seriously helpful page.
 - Snyk GitHub Repos - https://github.com/orgs/snyk/repositories?type=all On so many levels, awesome.

### Misc Links:
- ScamDroid Dashboard - https://github.com/Agastsya/ScamDroid-vulnerability-dashboard/tree/main - Pretty bitchin.
- React, markup with JSX - https://react.dev/learn/writing-markup-with-jsx
- CSS in React - https://www.reacttutorial.com/css-frameworks-in-react
