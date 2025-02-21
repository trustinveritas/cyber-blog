---
title: "Kali Linux Update Script"
description: ""
published: 2025-02-21
categories: ["Linux, Kali, Script, Update"]
---

# Kali Linux Update Script

1. **Installation of** `lolcat: lolcat` is available in the official Kali Linux repositories and can be installed with the following command:

```bash
sudo apt install lolcat
```

:::info
If lolcat isn't found use the following commands:  

```bash
sudo apt update
sudo apt install ruby -y
sudo gem install lolcat
```
**Check if lolcat is installed:**

```bash
lolcat --help
```
:::

2. **Create the update script:** Create a new bash script that performs the system update and colors the output with `lolcat`. Save the script under the name `update_kali.sh`, for example:

```bash
cd /usr/local/bin/
sudo nano update_kali.sh
```

```bash
#!/bin/bash

# Define colors for the output
GREEN="\033[1;32m"
ENDCOLOR="\033[0m"

# Funktion zur Ausgabe von Nachrichten mit lolcat
function print_message() {
    echo -e "$1" | lolcat
}

# Function for outputting messages with lolcat
print_message "${GREEN}Start system update...${ENDCOLOR}"
sudo apt update 2>&1 | lolcat
sudo apt full-upgrade -y 2>&1 | lolcat

# Clean up packages that are no longer required
print_message "${GREEN}Clean up packages that are no longer required...${ENDCOLOR}"
sudo apt autoremove -y 2>&1 | lolcat
sudo apt clean 2>&1 | lolcat

print_message "${GREEN}System update completed!${ENDCOLOR}"
```

3. **Make script executable:** Make sure that the script is executable:

```bash
sudo chmod +x update_kali.sh
```

5. **Execute the script:** Start the script with the following command:

```bash
./update_kali.sh
```

:::info
**Automation with cron:** You can set up a cron job to run the script automatically on a regular basis:
:::

1. Open the Crontab configuration:

```bash
crontab -e
```

2. Add the following line to run the script daily at 3 am:

```bash
0 3 * * * /Pfad/zu/Ihrem/update_kali.sh
```

:::tip
Create Systemd-Service  
So your system get's updated when kali is booting.
:::

## Create Systemd-Service
1. We create a systemd unit that executes the script at boot time.

```bash
sudo nano /etc/systemd/system/kali-update.service
```

**Add the following:**

```bash
[Unit]
Description=Kali Linux Auto Update Script
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/update_kali.sh
RemainAfterExit=true
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Save the file with `CTRL + X`, `Y`, then `ENTER`.

:::tip
Copy & Paste in Nano (Linux Terminal)  

1. **Copy (Mark and Copy)**
- **Use the mouse:** Simply select the text with your mouse and right-click to copy.
- **Using keyboard shortcuts:**
    - Move the cursor to the beginning of the text you want to copy.
    - Press `CTRL + 6` or (`CTRL + Shift + 6` in some terminals) to mark the text.
    - Move the cursor to the end of the text.
    - Press `ALT + 6` to copy the selected text.  

2. **Paste (Insert Copied Text)**
- **Use the mouse:** Right-click in the terminal and select "Paste."
- **Using the keyboard:** Move the cursor to the desired location and press:
    - `CTRL + U` (to paste the copied text).
:::

### Bonus: Cut & Paste in Nano
- Cut text: `CTRL + K`
- Paste text: `CTRL + U`
