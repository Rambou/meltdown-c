meltdown-c
==========

This project is a port of kao's program [Meltdown] to C.

It was constructed from mostly 3 things:
* The original v1.0 source released by kao
* Posts on [kao's blog] detailing the multiple security issues in [Deep Freeze]
* Reverse engineering the updated Meltdown v1.7 binary

There is no real reason to use this instead of Meltdown, but it may be
helpful for understanding the vulnerabilities present in later versions
of Deep Freeze, which aren't covered in the original Meltdown source code.
It also might be helpful if you just prefer reading C instead of Delphi.

Currently only Deep Freeze Enterprise v8.31 is supported.

[Deep Freeze]:http://www.faronics.com/products/deep-freeze/
[kao's blog]:http://lifeinhex.com/tag/meltdown/
[Meltdown]:http://lifeinhex.com/improving-meltdown/
