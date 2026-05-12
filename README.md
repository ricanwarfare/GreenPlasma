# GreenPlasma
GreenPlasma Windows CTFMON Arbitrary Section Creation Elevation of Privileges Vulnerability

For this one, I'm not dropping the full PoC, I stripped off the necessary code for a full SYSTEM shell. This is a huge challenge for CTF lovers out there.

The PoC will create an arbitrary memory section object in any directory object write-able by SYSTEM, if you're smart enough, you can turn this into a full privilege escalation as you can influence the newly created section to manipulate data, lots of services (and even kernel mode drivers) blindly trust certain paths since a standard user is normally not supposed to have write access to them.

Unsure if this works in Windows 10 but it works in Windows 11/2022/2026 for sure.

<img width="1115" height="628" alt="obj" src="https://github.com/user-attachments/assets/3a843a4b-8daf-4fc9-9d95-26f87b67031b" />
