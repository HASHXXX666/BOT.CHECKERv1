import discord
from discord.ext import commands
import ast

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)
tree = bot.tree  # Arbre pour les slash commands

# Patterns suspects style VirusTotal
SUSPICIOUS_PATTERNS = [
    "os.remove", "shutil.rmtree", "eval", "exec",
    "subprocess", "socket", "urllib", "input("
]

# -----------------------------
# /check : syntaxe + infos
# -----------------------------
@tree.command(name="check", description="Vérifie la syntaxe et donne des infos sur un script Python")
async def check(interaction: discord.Interaction, fichier: discord.Attachment):
    if not fichier.filename.endswith(".py"):
        await interaction.response.send_message("❌ Ce n'est pas un fichier Python !", ephemeral=True)
        return

    code = await fichier.read()
    code = code.decode("utf-8")

    try:
        tree_ast = ast.parse(code)
        syntax_status = "✅ Syntaxe correcte !"
    except SyntaxError as e:
        await interaction.response.send_message(f"❌ Erreur de syntaxe : {e}", ephemeral=True)
        return

    # Feedback complet
    lines = len(code.splitlines())
    functions = len([n for n in ast.walk(tree_ast) if isinstance(n, ast.FunctionDef)])
    classes = len([n for n in ast.walk(tree_ast) if isinstance(n, ast.ClassDef)])
    imports = [n.names[0].name for n in ast.walk(tree_ast) if isinstance(n, ast.Import)]
    imports += [n.module for n in ast.walk(tree_ast) if isinstance(n, ast.ImportFrom)]

    embed = discord.Embed(title="🛡️ Analyse du script", color=0x7289DA)
    embed.add_field(name="Fichier", value=fichier.filename, inline=False)
    embed.add_field(name="Syntaxe", value=syntax_status, inline=False)
    embed.add_field(name="Lignes", value=str(lines), inline=True)
    embed.add_field(name="Fonctions", value=str(functions), inline=True)
    embed.add_field(name="Classes", value=str(classes), inline=True)
    embed.add_field(name="Imports", value=", ".join(imports) if imports else "Aucun", inline=False)

    await interaction.response.send_message(embed=embed)

# -----------------------------
# /checkmalware : style VirusTotal
# -----------------------------
@tree.command(name="checkmalware", description="Analyse un script Python pour détecter des patterns suspects")
async def checkmalware(interaction: discord.Interaction, fichier: discord.Attachment):
    if not fichier.filename.endswith(".py"):
        await interaction.response.send_message("❌ Ce n'est pas un fichier Python !", ephemeral=True)
        return

    code = await fichier.read()
    code = code.decode("utf-8").lower()

    found = [p for p in SUSPICIOUS_PATTERNS if p in code]
    danger_level = len(found)

    embed = discord.Embed(title="🛡️ Analyse de sécurité", color=0xFFA500)
    embed.add_field(name="Fichier", value=fichier.filename, inline=False)

    if danger_level == 0:
        embed.add_field(name="Résultat", value="✅ Pas de pattern suspect détecté !", inline=False)
    else:
        embed.add_field(name="Résultat", value=f"⚠️ {danger_level} pattern(s) suspect(s) détecté(s)", inline=False)
        embed.add_field(name="Suspicious patterns", value=", ".join(found), inline=False)

    await interaction.response.send_message(embed=embed)

# -----------------------------
# /feedback : suggestions d'amélioration
# -----------------------------
@tree.command(name="feedback", description="Donne des suggestions pour améliorer un script Python")
async def feedback(interaction: discord.Interaction, fichier: discord.Attachment):
    if not fichier.filename.endswith(".py"):
        await interaction.response.send_message("❌ Ce n'est pas un fichier Python !", ephemeral=True)
        return

    code = await fichier.read()
    code = code.decode("utf-8")
    
    tree_ast = ast.parse(code)
    functions = [n for n in ast.walk(tree_ast) if isinstance(n, ast.FunctionDef)]
    classes = [n for n in ast.walk(tree_ast) if isinstance(n, ast.ClassDef)]
    
    suggestions = []

    # 1️⃣ Docstrings
    missing_docstrings = sum(1 for f in functions if ast.get_docstring(f) is None)
    if missing_docstrings > 0:
        suggestions.append(f"💡 {missing_docstrings} fonction(s) sans docstring. Ajouter des commentaires ou docstrings.")

    # 2️⃣ Classes
    if len(classes) == 0:
        suggestions.append("💡 Aucun classe détectée. Utiliser des classes pour mieux structurer le code si nécessaire.")

    # 3️⃣ Noms de variables
    if "x" in code or "y" in code or "a" in code:
        suggestions.append("💡 Certains noms de variables sont peu explicites. Choisir des noms clairs.")

    # 4️⃣ Longueur des fonctions
    long_funcs = [f.name for f in functions if len(f.body) > 20]
    if long_funcs:
        suggestions.append(f"💡 Certaines fonctions sont longues ({', '.join(long_funcs)}). Penser à les découper.")

    # 5️⃣ Imports
    imports = [n.names[0].name for n in ast.walk(tree_ast) if isinstance(n, ast.Import)]
    if not imports:
        suggestions.append("💡 Aucun import détecté. Vérifier si des libs pourraient simplifier le code.")

    if not suggestions:
        suggestions.append("✅ Le code est déjà assez propre !")

    embed = discord.Embed(title="📝 Suggestions d'amélioration", color=0x00FF00)
    embed.add_field(name="Fichier", value=fichier.filename, inline=False)
    embed.add_field(name="Conseils", value="\n".join(suggestions), inline=False)

    await interaction.response.send_message(embed=embed)

# -----------------------------
# Lancer le bot
# -----------------------------
@bot.event
async def on_ready():
    await tree.sync()  # Synchronise les slash commands sur le serveur
    print(f"Connecté comme {bot.user}")

bot.run("MTQxMjc3NDIyODk3Njk5MjMxNw.GF1dfn.BXOTBYRHw4hAmuCUxO2zOV08bhv6ElbbUQNH2c")