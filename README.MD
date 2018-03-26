# Cat Memo Note の暗号化に関する覚え書き
---

## このメモについて
Cat Memo Note 2.2 [ref#1] は暗号化が非常に弱かったので、ここに覚え書きを残しておくことにする。

## 1. 暗号化されたテキストファイルの構造
Cat Memo Note は暗号化された文章の前にいくつかのデータを記録する。
ここでは暗号化されたテキストファイルの構造について述べる。以下、断りがない限りファイルの先頭を0バイト目と数えることとする。
まず、最初の4バイトは固定で 0x07 0x11 0x12 0x07 となる。これはファイルを識別するためのシグニチャと思われる。
それに続いて16バイトのデータが並び（後述）、続いて 0x30 0x30 0xFF 0xFE の固定4バイトが記録される。
そして、暗号化された文章が記録される。暗号化された文章はファイルの24バイト目以降に記録されることとなる。

## 2. パスワード、暗号鍵、暗号化、ファイルへの書き出し
暗号化は平文と暗号鍵の排他的論理和を取ることによって行われる。暗号鍵は16バイトあり、入力されたパスワードを元に生成される。
以下ではパスワードから暗号鍵を導出する方法について述べる。

### 2.0. パスワードの拡張
16文字に満たない短いパスワードは16文字になるまで、入力されたパスワードに続き同じパスワードを繰り返す。
たとえば、パスワードが`pass12345`ならば拡張後のパスワードは`pass12345pass123`となる。
次に、拡張後のパスワードの(16 - 拡張される前のパスワードの文字数)文字目を0x00とする。ただし、拡張されたパスワードの先頭を0文字目と数える。
先の例では
```cpp
extended_pass[] = "pass123\05pass123";
```
となるであろう。 　
最終的に、これが拡張後のパスワードとなる。

### 2.1. 暗号鍵の導出
以下では、暗号鍵のiバイト目をK[i]と書くこととする。同様に、拡張されたパスワードのiバイト目をextended_pass[i]とする。 (i = 0,1,2,...,15)
暗号鍵のiバイト目は `K[i] = (extended_pass[15 - i] * (15 - i)) + (extended_pass[i] << 4) (定義2.1.1)` である。
**extended_pass[16 - 拡張される前のパスワードの文字数] は 0 であることに注意**

### 2.2. 暗号化　（複合化）
単純にXOR暗号である。暗号鍵は16バイト毎に同じものが使用される。
以下では平文Pのiバイト目をP[i]とし、対応する暗号文Pのiバイト目をC[i]とする。 (i = 0,1,2,...)
暗号文のiバイト目は `C[i] = P[i] ^ K[i % 16] (定義2.2.1)` となる。
逆に、平文のiバイト目は `P[i] = C[i] ^ k[i % 16] (定義2.2.2)` である。

### 2.3. 暗号鍵の変形とテキストファイルへの記録について
導出された暗号鍵は、さらに変形された上でテキストファイルに記録される。
変形後のデータiバイト目をh[i]と書くこととする。
h[i] は `h[i] = K[i] ^ K[15 - i] (i = 0,1,2,...15)　(定義2.3.1)` である。
この16バイトのデータがテキストファイル4バイト目から記録されているデータとなる。

## 3. 暗号鍵の復元について
ここでは、テキストファイルに記録されたh[i]から暗号鍵K[i]を復元する手法について述べる。
定義2.1.1および定義2.3.1によって
`h[0] = K[0] ^ K[15] = ((extended_pass[15] * 15) + (extended_pass[0] << 4)) ^ (extended_pass[15] << 4)` である。
`(extended_pass[0] << 4)` および `(extended_pass[15] << 4)` の下位4ビットは必ず0であり、`h[0]`の計算において
加算`+ (extended_pass[0] <<4)`と排他的論理和`^ (extended_pass[15] << 4)`は`h[0]`の下位4ビットに対しては影響しないことに注意すると、`h[0]`の下位4ビットは
`(extended_pass[15] * 15)` のみによって決定されることが分かる。
さらに`(extended_pass[15] * 15) = extended_pass[15] * (16 - 1) = 16 * extended_pass[15] - extended_pass[15]`であるから
`(extended_pass[15] * 15) MOD 16 = -extended_pass[15] = -(16 * (extended_pass[15] / 16) + (extended_pass[15] MOD 16)) = -(extended_pass[15] MOD 16)` となる。
以上のことから、`h[0]`の下位4ビットは`extended_pass[15]`の下位4ビットによって決定される。
ゆえに、`h[0]`の下位4ビットを与える`extended_pass[15]`の候補は高々16個しかなく、しかも、それぞれの候補に対し`(extended_pass[15] << 4) = K[15]`はただ一通りに定まる。

ここまでで、`h[0]`の下位4ビットのみによって`K[15]`（したがって`K[0]`も）が一通りに定まることが分かった。次に`K[1]`から`K[14]`までを見ていく。
各`i = 1,2,...14`において`K[i] = extended_pass[15 - i] * (15 - i) + (extended_pass[i] << 4)` であるから`K[i]`の下位4ビットは`extended_pass[15 - i] * (15 - i)`によって決定される。
したがって、`h[i] = K[i] ^ K[15 - i]`の下位4ビットは`(extended_pass[15 - i] * (15 - i)) ^ (extended_pass[i] * i)`の下位4ビットと一致するので、
各`h[i]`の下位4ビットから候補となる`extended_pass[i]`と`extended_pass[15 - i]`の組を絞り込むことが可能である。
しかも、`extended_pass[i]`がパスワードとして入力可能な文字であることを考慮すると、`extended_pass[i]`と`extended_pass[15 - i]`の組はそれほど多くはないであろう。
`extended_pass[i]`と`extended_pass[15 - i]`の組が見つかれば、そこから対応する`K[i]`と`K[15 - i]`を生成することができる。

## 4. さらなる絞り込み
候補となる暗号鍵の組`K[i]`,`K[15 - i]` と、その暗号鍵を生成するパスワード文字の組`extended_pass[i]`,`extended_pass[15 - i]`に対して、`extended_pass[i]`の生成規則から更なる絞り込みが可能である。
パスワードの拡張(2.0を参照)でも述べたように、16文字に満たないパスワードに対しては`extended_pass[i]`の生成において、同じパスワードが再び使用される。
従って、元のパスワードの文字数を`pass_length`としたとき、`extended_pass[pass_length + i] = extended_pass[i] (i = 0,1,2,... , 16 - pass_length - 1)`が成立するはずであるから、
この規則に反するパスワード文字の組と対応する暗号鍵の組は除外してよい。
また、`extended_pass[i] (i = 0,1,2,...,15)`において`extended_pass[i] = 0`となるような`extended_pass[i]`はただ一つである。
ゆえに、`extended_pass[i] = 0`となるような`extended_pass[i]`が一つでない場合、そのようなパスワードと対応する暗号鍵は除外してよい。

## 付録
[プログラム本体](CatMemoNotePassSearch.cpp)

入力例: CatMemoNotePassSearch.exe test_memo.txt --char_set=abcdefghijklmnopqrstuvwxyz
出力例:
searching key for h= 4c f 67 2c 2c e7 bf 6c 6c bf e7 2c 2c 67 f 4c
found key pair: 40 , c
(p = c , q = d)
found key pair: 40 , c
(p = d , q = t)
found key pair: 40 , c
(p = s , q = d)
found key pair: 40 , c
(p = t , q = t)
found key pair: 83 , 8c
(p = c , q = b)
found key pair: 95 , 9a
(p = e , q = s)
found key pair: 25 , 2a
(p = u , q = k)
found key pair: 52 , 35
(p = a , q = y)
found key pair: 9e , f9
(p = g , q = m)
found key pair: ea , 8d
(p = m , q = q)
found key pair: 36 , 51
(p = s , q = e)
found key pair: 82 , e5
(p = y , q = i)
found key pair: 50 , 7c
(p =   , q = u)
found key pair: a4 , 88
(p = l , q = f)
found key pair: 60 , 4c
(p = p , q = q)
found key pair: 9c , b0
(p = t , q = t)
found key pair: e0 , cc
(p = h , q = d)
found key pair: 24 , 8
(p = i , q = h)
found key pair: 68 , 44
(p = j , q = l)
found key pair: ac , 80
(p = k , q = p)
found key pair: 10 , 3c
(p = t , q = t)
found key pair: 54 , 78
(p = u , q = x)
found key pair: b5 , 52
(p = a , q = m)
found key pair: 29 , ce
(p = e , q = s)
found key pair: 1d , fa
(p = i , q = q)
found key pair: 91 , 76
(p = m , q = w)
found key pair: b6 , 9
(p = q , q = q)
found key pair: 5c , e3
(p = r , q = k)
found key pair: 2 , bd
(p = s , q = e)
found key pair: 1c , 70
(p = d , q = f)
found key pair: 2c , 40
(p = t , q =  )
key count for h = 4c: 1
key count for h = f: 3
key count for h = 67: 5
key count for h = 2c: 4
key count for h = 2c: 6
key count for h = ffffffe7: 4
key count for h = ffffffbf: 3
key count for h = 6c: 2
possible encryption keys are successfully recovered.
now check them
pass found: t e s t t e s t (NULL) e s t t e s t , len = 8
pass found: d e s t t e s t (NULL) e s t t e s t , len = 8
8640 keys in total
2 passwords are found
34558 pass are dropped


## 参考
ref1 - [Cat Memo Note](http://www.cc9.ne.jp/~pappara/)

## 改訂履歴
2018-Mar : 大昔に途中まで調べていて、そのまま興味を失って放置していたのを取りあえず完成
