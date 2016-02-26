meltdown-c
==========

**meltdown-c** is a password-recovery tool for [Deep Freeze].

Support
-------
Supported versions of Deep Freeze:
* Enterprise 5.x - 8.31.x

Usage
-----
In most cases, using **meltdown-c** is as simple as running it with
no arguments:

```
User@Machine C:\
> meltdown.exe
Detected Deep Freeze Enterprise version 8.31.220.5051
One-time Password: D978-E7F458DC
```

However, if Enterprise v7.19 or lower is detected, the user will be
asked to input the OTP token as the first argument:

```
User@Machine C:\
> meltdown.exe
usage: meltdown.exe <otp-token>
Detected Deep Freeze Enterprise version 7.00.220.3172

The OTP token cannot be automagically generated  for
this version of Deep Freeze Enterprise, please enter
it manually

User@Machine C:\
> meltdown.exe 0041D900
Detected Deep Freeze Enterprise version 7.00.220.3172
One-time Password: C55C-D922912F
```

Origins
-------
**meltdown-c** is a port of kao's program [Meltdown] to C.

It was constructed from mostly 3 things:
* The original v1.0 source released by kao
* Posts on [kao's blog] detailing the multiple security issues in Deep Freeze
* Reverse engineering the updated Meltdown v1.7 binary

There is no real reason to use this instead of Meltdown, but it may be
helpful for understanding the vulnerabilities present in later versions
of Deep Freeze, which aren't covered in the original Meltdown source code.
It also might be helpful if you just prefer reading C instead of Delphi.

[Deep Freeze]:http://www.faronics.com/products/deep-freeze/
[kao's blog]:http://lifeinhex.com/tag/meltdown/
[Meltdown]:http://lifeinhex.com/improving-meltdown/
