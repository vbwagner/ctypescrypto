from ctypescrypto.bio import Membio
import unittest

class TestRead(unittest.TestCase):
	def test_readshortstr(self):
		s="A quick brown fox jumps over a lazy dog"
		bio=Membio(s)
		data=bio.read()
		del bio
		self.assertEqual(data,s)
	def test_readlongstr(self):
		poem='''Eyes of grey--a sodden quay,
Driving rain and falling tears,
As the steamer wears to sea
In a parting storm of cheers.

Sing, for Faith and Hope are high--
None so true as you and I--
Sing the Lovers' Litany:
"Love like ours can never die!"

Eyes of black--a throbbing keel,
Milky foam to left and right;
Whispered converse near the wheel
In the brilliant tropic night.

Cross that rules the Southern Sky!
Stars that sweep and wheel and fly,
Hear the Lovers' Litany:
Love like ours can never die!"

Eyes of brown--a dusty plain
Split and parched with heat of June,
Flying hoof and tightened rein,
Hearts that beat the old, old tune.

Side by side the horses fly,
Frame we now the old reply
Of the Lovers' Litany:
"Love like ours can never die!"

Eyes of blue--the Simla Hills
Silvered with the moonlight hoar;
Pleading of the waltz that thrills,
Dies and echoes round Benmore.

"Mabel," "Officers," "Goodbye,"
Glamour, wine, and witchery--
On my soul's sincerity,
"Love like ours can never die!"

Maidens of your charity,
Pity my most luckless state.
Four times Cupid's debtor I--
Bankrupt in quadruplicate.

Yet, despite this evil case,
And a maiden showed me grace,
Four-and-forty times would I
Sing the Lovers' Litany:
"Love like ours can never die!"'''
		bio=Membio(poem)
		data=bio.read()
		self.assertEqual(data,poem)
		del bio
	def test_readparts(self):
		s="A quick brown fox jumps over the lazy dog"
		bio=Membio(s)
		a=bio.read(10)
		self.assertEqual(a,s[0:10])
		b=bio.read(9)
		self.assertEqual(b,s[10:19])
		c=bio.read()
		self.assertEqual(c,s[19:])
		d=bio.read()
		self.assertEqual(d,"")

class TestWrite(unittest.TestCase):
	def test_write(self):
		b=Membio()
		b.write("A quick brown ")
		b.write("fox jumps over ")
		b.write("the lazy dog.")
		self.assertEqual(str(b),"A quick brown fox jumps over the lazy dog.")


if __name__ == '__main__':
	unittest.main()
