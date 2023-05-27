#!/usr/bin/env python
"""

Implement the following routine:

	Integer invm(Integer, Integer)

such that invm(m, a) computes the inverse of a modulo m.
- Note that this routine will not always produce a result.
- If your programming language supports exceptions, 
then you should throw an exception if the inverse of a modulo m does not exist.
"""

import p2_egcd

def invm(m, a):
	g, x, y = p2_egcd.egcd(a, m)
	if g != 1:
		return None  # modular inverse does not exist
	else:
		return x % m

