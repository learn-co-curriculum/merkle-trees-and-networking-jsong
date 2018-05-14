# Merkle Trees and Networking

```python
# import everything and define a test runner function
from importlib import reload
from helper import run_test

import block
import ecc
import helper
import network
import script
import tx
```


```python
# Merkle Parent Example

from helper import double_sha256

tx_hash0 = bytes.fromhex('c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5')
tx_hash1 = bytes.fromhex('c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5')

merkle_parent = double_sha256(tx_hash0+tx_hash1)
print(merkle_parent.hex())
```

### Exercise 1

#### 1.1. Calculate the Merkle parent of these hashes:
```
f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0
3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181
```

#### 1.2. Make [this test](/edit/session7/helper.py) pass
```
helper.py:HelperTest:test_merkle_parent
```


```python
# Exercise 1.1

from helper import double_sha256

hex_hash1 = 'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0'
hex_hash2 = '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181'

# bytes.fromhex to get the bin hashes
# double_sha256 the combination
# hex() to see the result
```


```python
# Exercise 1.2

reload(helper)
run_test(helper.HelperTest('test_merkle_parent'))
```


```python
# Merkle Parent Level Example

from helper import double_sha256, merkle_parent
hex_hashes = [
    'c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5',
    'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5',
    'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0',
    '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181',
    '10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae',
    'b13a750047bc0bdceb2473e5fe488c2596d7a7124b4e716fdd29b046ef99bbf0',
]
hashes = [bytes.fromhex(x) for x in hex_hashes]
parent_level = []
for i in range(0, len(hex_hashes), 2):
    parent = merkle_parent(hashes[i], hashes[i+1])
    print(parent.hex())
    parent_level.append(parent)
```

### Exercise 2

#### 2.1. Calculate the next Merkle Parent Level given these hashes
```
8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd
7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800
ade48f2bbb57318cc79f3a8678febaa827599c509dce5940602e54c7733332e7
68b3e2ab8182dfd646f13fdf01c335cf32476482d963f5cd94e934e6b3401069
43e7274e77fbe8e5a42a8fb58f7decdb04d521f319f332d88e6b06f8e6c09e27
4f492e893bf854111c36cb5eff4dccbdd51b576e1cfdc1b84b456cd1c0403ccb
```

#### 2.2. Make [this test](/edit/session7/helper.py) pass.
```
helper.py:HelperTest:test_merkle_parent_level0
```


```python
# Exercise 2.1

from helper import merkle_parent

hex_hashes = [
    '8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd',
    '7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800',
    'ade48f2bbb57318cc79f3a8678febaa827599c509dce5940602e54c7733332e7',
    '68b3e2ab8182dfd646f13fdf01c335cf32476482d963f5cd94e934e6b3401069',
    '43e7274e77fbe8e5a42a8fb58f7decdb04d521f319f332d88e6b06f8e6c09e27',
    '4f492e893bf854111c36cb5eff4dccbdd51b576e1cfdc1b84b456cd1c0403ccb',
]

# bytes.fromhex to get all the hashes in binary
# initialize parent level
# skip by two: use range(0, len(hashes), 2)
    # calculate merkle_parent of i and i+1 hashes
    # print the hash's hex
    # add parent to parent level
```


```python
# Exercise 2.2

reload(helper)
run_test(helper.HelperTest('test_merkle_parent_level0'))
```


```python
# Odd Merkle Parent Level Example

from helper import double_sha256, merkle_parent
hex_hashes = [
    'c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5',
    'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5',
    'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0',
    '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181',
    '10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae',
]
hashes = [bytes.fromhex(x) for x in hex_hashes]
if len(hashes) % 2 == 1:
    hashes.append(hashes[-1])
parent_level = []
for i in range(0, len(hex_hashes), 2):
    parent = merkle_parent(hashes[i], hashes[i+1])
    print(parent.hex())
    parent_level.append(parent)
```

### Exercise 3

#### 3.1. Calculate the next Merkle Parent Level given these hashes
```
8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd
7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800
ade48f2bbb57318cc79f3a8678febaa827599c509dce5940602e54c7733332e7
68b3e2ab8182dfd646f13fdf01c335cf32476482d963f5cd94e934e6b3401069
43e7274e77fbe8e5a42a8fb58f7decdb04d521f319f332d88e6b06f8e6c09e27
```

#### 3.2. Make [this test](/edit/session7/helper.py) pass.
```
helper.py:HelperTest:test_merkle_parent_level1
```


```python
# Exercise 3.1

from helper import merkle_parent

hex_hashes = [
    '8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd',
    '7f4e6f9e224e20fda0ae4c44114237f97cd35aca38d83081c9bfd41feb907800',
    'ade48f2bbb57318cc79f3a8678febaa827599c509dce5940602e54c7733332e7',
    '68b3e2ab8182dfd646f13fdf01c335cf32476482d963f5cd94e934e6b3401069',
    '43e7274e77fbe8e5a42a8fb58f7decdb04d521f319f332d88e6b06f8e6c09e27',
]

# bytes.fromhex to get all the hashes in binary
# if the number of hashes is odd, duplicate the last one
# initialize parent level
# skip by two: use range(0, len(hashes), 2)
    # calculate merkle_parent of i and i+1 hashes
    # print the hash's hex
    # add parent to parent level
```


```python
# Exercise 3.2

reload(helper)
run_test(helper.HelperTest('test_merkle_parent_level1'))
```


```python
# Merkle Root Example

from helper import double_sha256, merkle_parent_level

hex_hashes = [
    'c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5',
    'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5',
    'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0',
    '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181',
    '10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae',
    '7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161',
    '8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc',
    'dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877',
    'b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59',
    '95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c',
    '2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908',
    'b13a750047bc0bdceb2473e5fe488c2596d7a7124b4e716fdd29b046ef99bbf0',
]

current_level = [bytes.fromhex(x) for x in hex_hashes]
while len(current_level) > 1:
    current_level = merkle_parent_level(current_level)
print(current_level[0].hex())
```

### Exercise 4

#### 4.1. Calculate the Merkle Root given these hashes
```
42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e
94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4
959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953
a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2
62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577
766900590ece194667e9da2984018057512887110bf54fe0aa800157aec796ba
e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208
921b8cfd3e14bf41f028f0a3aa88c813d5039a2b1bceb12208535b0b43a5d09e
15535864799652347cec66cba473f6d8291541238e58b2e03b046bc53cfe1321
1c8af7c502971e67096456eac9cd5407aacf62190fc54188995666a30faf99f0
3311f8acc57e8a3e9b68e2945fb4f53c07b0fa4668a7e5cda6255c21558c774d
```

#### 4.2. Make [this test](/edit/session7/helper.py) pass.
```
helper.py:HelperTest:test_merkle_root
```


```python
# Exercise 4.1

from helper import double_sha256, merkle_parent_level
hex_hashes = [
    '42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e',
    '94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4',
    '959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953',
    'a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2',
    '62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577',
    '766900590ece194667e9da2984018057512887110bf54fe0aa800157aec796ba',
    'e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208',
    '921b8cfd3e14bf41f028f0a3aa88c813d5039a2b1bceb12208535b0b43a5d09e',
    '15535864799652347cec66cba473f6d8291541238e58b2e03b046bc53cfe1321',
    '1c8af7c502971e67096456eac9cd5407aacf62190fc54188995666a30faf99f0',
    '3311f8acc57e8a3e9b68e2945fb4f53c07b0fa4668a7e5cda6255c21558c774d',
]

# bytes.fromhex to get all the hashes in binary
# initialize current level to be the hashes
# loop until current_level has only 1 element
    # make the current level the parent level
# print the root's hex
```


```python
# Exercise 4.2

reload(helper)
run_test(helper.HelperTest('test_merkle_root'))
```


```python
# Block Merkle Root Example

from helper import double_sha256, merkle_parent_level, merkle_root
tx_hex_hashes = [
    '42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e',
    '94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4',
    '959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953',
    'a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2',
    '62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577',
    '766900590ece194667e9da2984018057512887110bf54fe0aa800157aec796ba',
    'e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208',
]
current_level = [bytes.fromhex(x)[::-1] for x in tx_hex_hashes]
print(merkle_root(current_level)[::-1].hex())
```

### Exercise 5

#### 5.1. Validate the merkle root for this block on Testnet:
Block Hash:
```
0000000000000451fa80fcdb243b84c35eaae215a85a8faa880559e8239e6f20
```

https://api.blockcypher.com/v1/btc/test3/blocks/0000000000000451fa80fcdb243b84c35eaae215a85a8faa880559e8239e6f20

Transaction Hashes:
```
42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e
94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4
959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953
a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2
62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577
766900590ece194667e9da2984018057512887110bf54fe0aa800157aec796ba
e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208
921b8cfd3e14bf41f028f0a3aa88c813d5039a2b1bceb12208535b0b43a5d09e
15535864799652347cec66cba473f6d8291541238e58b2e03b046bc53cfe1321
1c8af7c502971e67096456eac9cd5407aacf62190fc54188995666a30faf99f0
3311f8acc57e8a3e9b68e2945fb4f53c07b0fa4668a7e5cda6255c21558c774d
```

#### 5.2. Make [these tests](/edit/session7/block.py) pass.
```
block.py:BlockTest:test_validate_merkle_root
block.py:BlockTest:test_calculate_merkle_tree
```


```python
# Exercise 5.1

from helper import double_sha256, merkle_root

tx_hex_hashes = [
    '42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e',
    '94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4',
    '959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953',
    'a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2',
    '62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577',
    '766900590ece194667e9da2984018057512887110bf54fe0aa800157aec796ba',
    'e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208',
    '921b8cfd3e14bf41f028f0a3aa88c813d5039a2b1bceb12208535b0b43a5d09e',
    '15535864799652347cec66cba473f6d8291541238e58b2e03b046bc53cfe1321',
    '1c8af7c502971e67096456eac9cd5407aacf62190fc54188995666a30faf99f0',
    '3311f8acc57e8a3e9b68e2945fb4f53c07b0fa4668a7e5cda6255c21558c774d',
]

# bytes.fromhex and reverse ([::-1]) to get all the hashes in binary
# get the merkle root
# hex() the reversed root
```


```python
# Exercise 5.2

reload(block)
run_test(block.BlockTest('test_validate_merkle_root'))
run_test(block.BlockTest('test_calculate_merkle_tree'))
```


```python
# Merkle Path Example

import math

total_levels = math.ceil(math.log(16, 2))
merkle_path = []
index = 10
for i in range(total_levels):
    merkle_path.append(index)
    index = index // 2
print(merkle_path)
```

### Exercise 6

#### 6.1. Get the Merkle Path for an item at index 13 (0-base) in 27 items.

#### 6.2. Make [this test](/edit/session7/helper.py) pass.
```
helper.py:HelperTest:test_merkle_path
```


```python
# Exercise 6.1

import math

num_items = 27
index = 13

# get the total number of levels possible (math.ceil(math.log(num_items, 2)))
# initialize merkle path array
# loop through number of levels
    # add the index to merkle path
    # index integer div by 2 to get the index at the next level
# print merkle path
```


```python
# Exercise 6.2

reload(helper)
run_test(helper.HelperTest('test_merkle_path'))
```


```python
# Merkle Proof Example
from block import Block, Proof
from helper import int_to_little_endian, merkle_path

hex_tx_hashes = [
    "9745f7173ef14ee4155722d1cbf13304339fd00d900b759c6f9d58579b5765fb",
    "5573c8ede34936c29cdfdfe743f7f5fdfbd4f54ba0705259e62f39917065cb9b",
    "82a02ecbb6623b4274dfcab82b336dc017a27136e08521091e443e62582e8f05",
    "507ccae5ed9b340363a0e6d765af148be9cb1c8766ccc922f83e4ae681658308",
    "a7a4aec28e7162e1e9ef33dfa30f0bc0526e6cf4b11a576f6c5de58593898330",
    "bb6267664bd833fd9fc82582853ab144fece26b7a8a5bf328f8a059445b59add",
    "ea6d7ac1ee77fbacee58fc717b990c4fcccf1b19af43103c090f601677fd8836",
    "457743861de496c429912558a106b810b0507975a49773228aa788df40730d41",
    "7688029288efc9e9a0011c960a6ed9e5466581abf3e3a6c26ee317461add619a",
    "b1ae7f15836cb2286cdd4e2c37bf9bb7da0a2846d06867a429f654b2e7f383c9",
    "9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab",
    "b3a92b5b255019bdaf754875633c2de9fec2ab03e6b8ce669d07cb5b18804638",
    "b5c0b915312b9bdaedd2b86aa2d0f8feffc73a2d37668fd9010179261e25e263",
    "c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800",
    "c555bc5fc3bc096df0a0c9532f07640bfb76bfe4fc1ace214b8b228a1297a4c2",
    "f9dbfafc3af3400954975da24eb325e326960a25b87fffe23eef3e7ed2fb610e",
    "8e694f5092f6a644ab587ca445f9e949e4f5991d3c3c72bd4574a7c9896a2402",
    "9cc887977168f430f4f896dfc6fc7379834733ce938abe7cd8a1a668d1ea1841",
]
tx_hash = bytes.fromhex('9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab')
b = Block(
    version=536870914,
    prev_block=bytes.fromhex('00000000000002dda81fd83ac5b944ad88592a213bfaf54bffad68725c782639'),
    merkle_root=bytes.fromhex('f2710c8f3652ec6bfe79769458ae4be8117cad46964ce9dab9ce570bcb2ff9b0'),
    bits=int_to_little_endian(437256176, 4),
    nonce=b'\x00\x00\x00\x00',
    timestamp=1512503014,
    tx_hashes=[bytes.fromhex(h) for h in hex_tx_hashes],
)
b.calculate_merkle_tree()
index = b.tx_hashes.index(tx_hash)
proof_hashes = []
current_index = index
for level in b.merkle_tree:
    if current_index % 2 == 1:
        partner = current_index - 1
    else:
        partner = current_index + 1
    proof_hashes.append(level[partner])
    current_index //= 2
proof = Proof(b.merkle_root, tx_hash, index, proof_hashes)
print(proof)
```

### Exercise 7

#### 7.1. Create a Merkle Proof for this transaction
Transaction Hash:
```
e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208
```

Block Hex:
```
00000020fcb19f7895db08cadc9573e7915e3919fb76d59868a51d995201000000000000acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed691cfa85916ca061a00000000
```

Transaction Hashes:
```
42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e
94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4
959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953
a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2
62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577
766900590ece194667e9da2984018057512887110bf54fe0aa800157aec796ba
e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208
921b8cfd3e14bf41f028f0a3aa88c813d5039a2b1bceb12208535b0b43a5d09e
15535864799652347cec66cba473f6d8291541238e58b2e03b046bc53cfe1321
1c8af7c502971e67096456eac9cd5407aacf62190fc54188995666a30faf99f0
3311f8acc57e8a3e9b68e2945fb4f53c07b0fa4668a7e5cda6255c21558c774d
```

#### 7.2. Make [this test](/edit/session7/block.py) pass.
```
block.py:BlockTest:test_create_merkle_proof
```


```python
# Exercise 7.1

from io import BytesIO

from block import Block, Proof
from helper import merkle_path

tx_hash = bytes.fromhex('e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208')
tx_hex_hashes = [
    '42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e',
    '94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4',
    '959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953',
    'a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2',
    '62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577',
    '766900590ece194667e9da2984018057512887110bf54fe0aa800157aec796ba',
    'e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208',
    '921b8cfd3e14bf41f028f0a3aa88c813d5039a2b1bceb12208535b0b43a5d09e',
    '15535864799652347cec66cba473f6d8291541238e58b2e03b046bc53cfe1321',
    '1c8af7c502971e67096456eac9cd5407aacf62190fc54188995666a30faf99f0',
    '3311f8acc57e8a3e9b68e2945fb4f53c07b0fa4668a7e5cda6255c21558c774d',
]
stream = BytesIO(bytes.fromhex('00000020fcb19f7895db08cadc9573e7915e3919fb76d59868a51d995201000000000000acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed691cfa85916ca061a00000000'))
b = Block.parse(stream)
b.tx_hashes = [bytes.fromhex(x) for x in tx_hex_hashes]

# calculate the merkle tree first
# get the index of the tx_hash in the list of tx_hashes (b.tx_hashes.index(tx_hash))
# initialize the proof hashes
# initialize the current index to the index at the lowest level (index)
# loop through merkle tree levels
    # if the current index is odd, the partner index is - 1
    # if the current index is even, the partner index is + 1
    # partner is at the level's partner index
    # add the partner to proof hashes
    # update current_index to be integer divide by 2
# create the Proof object
# print the proof
```


```python
# Exercise 7.2

reload(block)
run_test(block.BlockTest('test_create_merkle_proof'))
```

### Exercise 8

#### 8.1. Verify a Merkle Proof
Transaction Hash:
```
e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208
```

Index:
```
6
```

Merkle Root:
```
4297fb95a0168b959d1469410c7527da5d6243d99699e7d041b7f3916ba93301
```

Merkle Proof:
```
9ed0a5430b5b530822b1ce1b2b9a03d513c888aaa3f028f041bf143efd8c1b92
1dc4b438b3a842bcdd46b6ea5a4aac8d66be858b0ba412578027a1f1fe838c51
156f3662b07aaa4a0d9762faaa8c18afe4c211ff92eb1eae1952aa66627bbf2e
524c93c6dd0874c5fd9e4e57cfe83176e3c2841c973afb4043d225c22cc52983
```

#### 8.2. Make [this test](/edit/session7/block.py) pass.
```
block.py:BlockTest:test_verify_merkle_proof
```


```python
# Exercise 8.1

from block import Proof
from helper import double_sha256, merkle_root, merkle_path, merkle_parent

tx_hash = bytes.fromhex('e8270fb475763bc8d855cfe45ed98060988c1bdcad2ffc8364f783c98999a208')
merkle_root = bytes.fromhex('4297fb95a0168b959d1469410c7527da5d6243d99699e7d041b7f3916ba93301')
proof_hex_hashes = [
    '9ed0a5430b5b530822b1ce1b2b9a03d513c888aaa3f028f041bf143efd8c1b92',
    '1dc4b438b3a842bcdd46b6ea5a4aac8d66be858b0ba412578027a1f1fe838c51',
    '156f3662b07aaa4a0d9762faaa8c18afe4c211ff92eb1eae1952aa66627bbf2e',
    '524c93c6dd0874c5fd9e4e57cfe83176e3c2841c973afb4043d225c22cc52983',
]
proof_hashes = [bytes.fromhex(x) for x in proof_hex_hashes]
index = 6

# get the current hash (reverse tx_hash as it needs to be little endian)
# initialize the current_index to the index
# loop through proof hashes
    # if current_index is odd, proof_hash is on the left
    # if current_index is even, proof_hash is on the right
    # update current_index to be integer divide by 2
# see if the current one reversed is the same as merkle root
```


```python
# Exercise 8.2

reload(block)
run_test(block.BlockTest('test_verify_merkle_proof'))
```

### Exercise 9

#### Check the cheat sheet for the network message structure.

#### 9.1. Parse this message
```
f9beb4d976657261636b000000000000000000005df6e0e2
```

#### 9.2. Make [these test](/edit/session7/network.py) pass.
```
network.py:NetworkTest:test_parse
network.py:NetworkTest:test_serialize
```


```python
# Exercise 9.1

msg = bytes.fromhex('f9beb4d976657261636b000000000000000000005df6e0e2')

# first 4 are network magic
# next 12 are command
# next 4 are payload length
# next 4 are checksum
# rest is payload
```


```python
# Exercise 9.2

reload(network)
run_test(network.NetworkEnvelopeTest('test_parse'))
run_test(network.NetworkEnvelopeTest('test_serialize'))
```

### Exercise 10

#### 10.1. Parse this message
```
f9beb4d974780000000000000000000002010000e293cdbe01000000016dbddb085b1d8af75184f0bc01fad58d1266e9b63b50881990e4b40d6aee3629000000008b483045022100f3581e1972ae8ac7c7367a7a253bc1135223adb9a468bb3a59233f45bc578380022059af01ca17d00e41837a1d58e97aa31bae584edec28d35bd96923690913bae9a0141049c02bfc97ef236ce6d8fe5d94013c721e915982acd2b12b65d9b7d59e20a842005f8fc4e02532e873d37b96f09d6d4511ada8f14042f46614a4c70c0f14beff5ffffffff02404b4c00000000001976a9141aa0cd1cbea6e7458a7abad512a9d9ea1afb225e88ac80fae9c7000000001976a9140eab5bea436a0484cfab12485efda0b78b4ecc5288ac00000000
```



```python
# Exercise 10.1

from io import BytesIO

from network import NetworkEnvelope

stream = BytesIO(bytes.fromhex('f9beb4d974780000000000000000000002010000e293cdbe01000000016dbddb085b1d8af75184f0bc01fad58d1266e9b63b50881990e4b40d6aee3629000000008b483045022100f3581e1972ae8ac7c7367a7a253bc1135223adb9a468bb3a59233f45bc578380022059af01ca17d00e41837a1d58e97aa31bae584edec28d35bd96923690913bae9a0141049c02bfc97ef236ce6d8fe5d94013c721e915982acd2b12b65d9b7d59e20a842005f8fc4e02532e873d37b96f09d6d4511ada8f14042f46614a4c70c0f14beff5ffffffff02404b4c00000000001976a9141aa0cd1cbea6e7458a7abad512a9d9ea1afb225e88ac80fae9c7000000001976a9140eab5bea436a0484cfab12485efda0b78b4ecc5288ac00000000'))
```

### Exercise 11

Use https://bitnodes.earn.com/nodes/ to find nodes to connect to.

#### 11.1. Run the code below and parse some messages

#### Bonus: Run the connect.py script in the terminal to see how asynchronous connections can work


```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
msg = bytes.fromhex('f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001')
s.connect(('46.101.99.121', 8333))
s.sendall(msg)
data = s.recv(200)
print(data.hex())
```
