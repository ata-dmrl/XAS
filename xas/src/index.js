// src/index.js
const { banner } = require("./banner");
const readline = require("readline");
const { XasContext, handleCommand } = require("./commands");
const { checkAllTools } = require("./toolCheck");
const registry = require("./tools/registry");

banner();
checkAllTools();

function promptFor(mode) {
  if (mode === "scan") return "\x1b[32mxas\x1b[33m<\x1b[36mscan\x1b[33m>\x1b[0m ";
  if (mode === "safe") return "\x1b[32mxas\x1b[33m<\x1b[35msafe\x1b[33m>\x1b[0m ";
  return "\x1b[32mxas\x1b[33m>\x1b[0m ";
}

function startRepl() {
  const ctx = new XasContext();

  console.log("\n\x1b[1m\x1b[32mXAS Security Console\x1b[0m \x1b[90mv2.0.0\x1b[0m");
  console.log("\x1b[90mKomutlar için 'help' yazın.\x1b[0m\n");

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: promptFor(ctx.mode),
    completer: (line) => {
      const commands = [
        "help", "tools", "clear", "exit", "quit", "back",
        "scope", "scope add", "scope remove", "scope clear",
        "install", ...registry.all().map(a => `install ${a.name}`),
        "launch", ...registry.launchable().map(a => `launch ${a.name}`),
        "start", "guide", "diff",
        "safe", "show", "run", "run --dry", "rollback", "select", "select all",
        "set transport ssh", "set transport telnet", "set user", "set pass", "set key", "set file",
        "scan", "scan full",
        "run nmap", "run nmap full", "run zap", "run zap full", "run msfconsole",
        "load nmap", "load zap",
        "list", "list sev=critical", "list sev=high", "list sev=medium", "list sev=low", "list sev=info",
        "search", "detail", "fix", "fix auto", "stats",
        "report", "export json", "export csv"
      ];
      const hits = commands.filter(c => c.startsWith(line.trim()));
      return [hits.length ? hits : commands, line];
    }
  });

  rl.prompt();

  rl.on("line", async line => {
    try {
      await handleCommand(ctx, line);
    } catch (e) {
      console.log("\x1b[31m  Beklenmeyen hata:\x1b[0m", e.message);
    }
    rl.setPrompt(promptFor(ctx.mode));
    rl.prompt();
  });
}

startRepl();