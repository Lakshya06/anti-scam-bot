import os, re
import discord
import datetime
from discord.ext import commands
from dotenv import load_dotenv

load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")
LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID") or 0)
IGNORE_ROLE_IDS = {int(x) for x in (os.getenv("IGNORE_ROLE_IDS") or "").split(",") if x.strip()}
AUTO_BAN_AFTER = int(os.getenv("AUTO_BAN_AFTER") or 0)

# Regex for bad file names / URLs:
# Matches: 1.png, 2.jpg, image.png, image0.jpg, image123.gif, img12.webp
BANNED_REGEX = re.compile(r'(?:^|/)(?:\d+|image\d*|img\d*)\.(?:png|jpe?g|webp|gif)(?:\?.*)?$', re.IGNORECASE)

# Only check Discord CDN domains
SUSPICIOUS_DOMAINS = ["cdn.discordapp.com", "media.discordapp.net"]

intents = discord.Intents.default()
intents.message_content = True
intents.messages = True
intents.guilds = True
bot = commands.Bot(command_prefix="!", intents=intents)

offenses = {}

@bot.event
async def on_ready():
    print(f"Logged in as {bot.user} (id: {bot.user.id})")

def is_whitelisted(member: discord.Member) -> bool:
    if member.guild_permissions.manage_messages:
        return True
    for role in member.roles:
        if role.id in IGNORE_ROLE_IDS:
            return True
    return False

# async def log_action(guild: discord.Guild, text: str):
#     """Send log message to console and log channel if set."""
#     print(f"[LOG] {text}")
#     if LOG_CHANNEL_ID:
#         ch = guild.get_channel(LOG_CHANNEL_ID)
#         if ch:
#             try:
#                 await ch.send(text)
#             except Exception as e:
#                 print(f"[WARN] Could not send log to channel: {e}")


async def log_action(guild: discord.Guild, message: discord.Message, reason: str, files=None):
    ts = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    print(f"[LOG {ts}] {reason} | Author={message.author} | Channel=#{message.channel} | Content={message.content}")

    if LOG_CHANNEL_ID:
        ch = guild.get_channel(LOG_CHANNEL_ID)
        if ch:
            try:
                embed = discord.Embed(
                    title="Suspicious Message Deleted",
                    description=f"**Reason:** {reason}",
                    color=discord.Color.red(),
                    timestamp=datetime.datetime.now(datetime.UTC)
                )
                embed.add_field(name="User", value=f"{message.author} ({message.author.id})", inline=False)
                embed.add_field(name="Channel", value=message.channel.mention, inline=False)

                if message.content:
                    embed.add_field(name="Message Content", value=message.content[:1024], inline=False)

                # Add embed previews (external URLs)
                if message.embeds:
                    emb_texts = []
                    for i, emb in enumerate(message.embeds, start=1):
                        parts = []
                        if emb.title:
                            parts.append(f"**Title:** {emb.title}")
                        if emb.description:
                            parts.append(f"**Desc:** {emb.description[:200]}")
                        if emb.url:
                            parts.append(f"**URL:** {emb.url}")
                        emb_texts.append("\n".join(parts))
                    if emb_texts:
                        embed.add_field(name="Embeds", value="\n\n".join(emb_texts)[:1024], inline=False)

                embed.set_footer(text=f"Message ID: {message.id} | Time: {ts}")

                # Send embed + files (attachments re-uploaded)
                await ch.send(embed=embed, files=files or None)

            except Exception as e:
                print(f"[WARN] Could not send log to channel: {e}")


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot:
        return
    if isinstance(message.channel, discord.DMChannel):
        return
    if is_whitelisted(message.author):
        return

    suspicious = False
    reason = None

    # Check forwarded content if available
    snapshots = getattr(message, "message_snapshots", [])
    for snap in snapshots:
        snap_content = getattr(snap, "content", "").lower()
        for domain in SUSPICIOUS_DOMAINS:
            if domain in snap_content and BANNED_REGEX.search(snap_content):
                suspicious = True
                reason = "Suspicious link in forwarded message content"
                break
        if suspicious:
            break

    # --- Check attachments ---
    if message.attachments:
        for att in message.attachments:
            filename = (att.filename or "").lower()
            print(f"[DEBUG] Attachment detected from {message.author}: filename={att.filename}, url={att.url}")
            if BANNED_REGEX.search(filename):
                suspicious = True
                reason = f"Suspicious attachment `{filename}`"

    # --- Check embeds (links that render images) ---
    if message.embeds:
        for emb in message.embeds:
            if emb.url:
                url = emb.url.lower()
                print(f"[DEBUG] Embed detected from {message.author}: url={url}")
                if any(domain in url for domain in SUSPICIOUS_DOMAINS) and BANNED_REGEX.search(url):
                    suspicious = True
                    reason = f"Suspicious embed link `{url}`"

    # --- Check raw message content for suspicious links ---
    content = message.content.lower()
    for domain in SUSPICIOUS_DOMAINS:
        if domain in content:
            if BANNED_REGEX.search(content):
                suspicious = True
                reason = "Suspicious link in message content"

    # --- Take action ---
    if suspicious:
        files = []
        if message.attachments:
            for att in message.attachments:
                try:
                    file = await att.to_file()
                    files.append(file)
                except Exception as e:
                    print(f"[ERROR] Could not fetch attachment {att.filename}: {e}")

        try:
            # Log before deletion
            await log_action(message.guild, message, reason, files=files)

            # Delete the original message
            await message.delete()

            print(f"[ACTION] Deleted message from {message.author} - {reason}")
        except discord.Forbidden:
            print("[ERROR] Bot lacks Manage Messages permission.")
            return
        except Exception as e:
            print(f"[ERROR] Failed to delete message: {e}")
            return

        # Auto-ban handling
        if AUTO_BAN_AFTER > 0:
            uid = message.author.id
            offenses[uid] = offenses.get(uid, 0) + 1
            if offenses[uid] >= AUTO_BAN_AFTER:
                try:
                    await message.guild.ban(message.author, reason="Auto-ban: repeated scam messages")
                    await log_action(message.guild, f"Banned {message.author} after {offenses[uid]} offenses.")
                except Exception as e:
                    print(f"[ERROR] Failed to ban: {e}")
        return

    # Debug log
    print(f"[DEBUG] Message from {message.author}: {message.content[:50]}")

    await bot.process_commands(message)

if not TOKEN:
    print("ERROR: DISCORD_TOKEN not found in environment.")
    exit(1)

bot.run(TOKEN)
