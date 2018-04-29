from ctypescrypto.bio import Membio
import unittest
import sys
if sys.version[0]>'2':
    def unicode(b):
        return str(b)


class TestRead(unittest.TestCase):
    def test_readshortstr(self):
        s=b"A quick brown fox jumps over a lazy dog"
        bio=Membio(s)
        data=bio.read()
        self.assertEqual(data,s)
        data2=bio.read()
        self.assertEqual(data2,b"")
        del bio
    def test_readwithlen(self):
        s=b"A quick brown fox jumps over a lazy dog"
        bio=Membio(s)
        data=bio.read(len(s))
        self.assertEqual(data,s)
        data2=bio.read(5)
        self.assertEqual(data2,b"")
    def test_readwrongtype(self):
        s=b"A quick brown fox jumps over a lazy dog"
        bio=Membio(s)
        with self.assertRaises(TypeError):
            data=bio.read("5")
    def test_reset(self):
        s=b"A quick brown fox jumps over a lazy dog"
        bio=Membio(s)
        data=bio.read()
        bio.reset()
        data2=bio.read()
        del bio
        self.assertEqual(data,data2)
        self.assertEqual(data,s)
    def test_readlongstr(self):
        poem=b'''Eyes of grey--a sodden quay,
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
        s=b"A quick brown fox jumps over the lazy dog"
        bio=Membio(s)
        a=bio.read(10)
        self.assertEqual(a,s[0:10])
        b=bio.read(9)
        self.assertEqual(b,s[10:19])
        c=bio.read()
        self.assertEqual(c,s[19:])
        d=bio.read()
        self.assertEqual(d,b"")

class TestWrite(unittest.TestCase):
    def test_write(self):
        b=Membio()
        b.write(b"A quick brown ")
        b.write(b"fox jumps over ")
        b.write(b"the lazy dog.")
        self.assertEqual(str(b),"A quick brown fox jumps over the lazy dog.")

    def test_unicode(self):
        b=Membio()
        s=b'\xd0\xba\xd0\xb0\xd0\xba \xd1\x8d\xd1\x82\xd0\xbe \xd0\xbf\xd0\xbe-\xd1\x80\xd1\x83\xd1\x81\xd1\x81\xd0\xba\xd0\xb8'
        b.write(s)
        self.assertEqual(unicode(b),u'\u043a\u0430\u043a \u044d\u0442\u043e \u043f\u043e-\u0440\u0443\u0441\u0441\u043a\u0438')
    def test_unicode2(self):
        b=Membio()
        u=u'\u043a\u0430\u043a \u044d\u0442\u043e \u043f\u043e-\u0440\u0443\u0441\u0441\u043a\u0438'
        b.write(u)
        self.assertEqual(unicode(b),u)
if __name__ == '__main__':
    unittest.main()
