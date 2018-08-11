# SimpleChain

The SimpleChain demonstrate a basics of blockchain technology. You could easily use it to store a date (encrypted or not) at blockchain

# Features
- [x] SHA256 hashing
- [x] RSA 2048 Client's message encryption
- [x] SDP or interconnection between nodes 
- [x] JSON checking tool (genM)
- [ ] Storing blockchain data at DB
- [ ] Front-End Html


# To connect

- Node predifined IP: 127.0.0.1:8080

## Structure Connection
> GO Message Structure:
```
type Message struct {
	Type      string // Client or Noda
	Data      string // Only for a Client
	BlockData Block  
}
type Block struct {
	Index     int     // Only for a Noda
	Timestamp string  // Only for a Noda
	PubKey    string  // Both
	Data      string  // Only for a Noda
	Hash      string  // Only for a Noda
	PrevHash  string  // Only for a Noda
}
```
# As a Client
In accordance to a SimpleChain' JSON structure you should use only 3 parameters to send your data to a SimpleChain:
- Type (Client)
- Data (Raw or encrypted with your PrivateKey)
- PubKey (Nothing or your PublicKey at `PemString` to encrypt next message for you)

> Example of JSON Structure:
```
{"Type":"Client",
"Data":"Client Data",
"BlockData":{"Index":Will be passed at Client's mode,
"Timestamp":"2018-07-07 23:19:21.847017015 +0300 MSK m=+49.614843062",
"PubKey":"-----BEGIN RSA PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxNHEyAqbSzPVXI26VNXC\nHApXYrWhoLcrEVm7iDVaPQZ1W5cLLp9ZrKH1CrO3L32Z3OS0ZugEe72ofjzWrxfA\nFg0GXxwIta+QcattynCeaw1USBfaKAyZf1+tjXfZ7bmL7Ux/faTkMxQU+1K3XVGW\nhuoqvuW6OXw4pyABHlD7uHRZOSuYpTAaOu8W5ukPMXxo/GyJaWZa8A06v9Eg6sfx\njA7RoanZgxknfctWIHygUhC6NrjfcBjpzeAh9pKleLJf/UEqpZACisdPQP5Sel/F\nTaQl58eJskp0S7ggD+6M1tWUu2FXHIr6avzfVLWKYEqdmxPzNCMSOnBiDfLSuCLq\ntWvHr29Z1fF/S2zW3sBbWBcIQ7600MgzoZWvhw0ZhaMaJnuwb1G9oW0r3XUMuZPQ\nruEMef8b6p82ZUH2hS9VEhSk0ReNZ9Jqnj+Foa7XS7Er8TGQmtmgYsDV/qj+AF+J\ntNCSrazvHFyOKCMwz9KGtjGgzKgA7y+Gg33HnyUJlDP2uT6uZazVKzqF3j5tx06/\njxqmO3MNJiZ/LXwh3v+xB/U9yj3waDZ7Wsw+ZvjC3L/prsJaMGiyMm1zRGNSW47V\nIC6LJVF2XX/j8unjGbZymTmXyD3rZL4NCAbOfkYYHH7C+B8SnetglcrSQhegTV++\nFHYe+7OQkKLPt1FjALNEdSsCAwEAAQ==\n-----END RSA PUBLIC KEY-----\n",
"Data":"Will be passed at Client's mode",
"Hash":"Will be passed at Client's mode",
"PrevHash":"Will be passed at Client's mode"}}
```

# As a Noda
In accordance to a SimpleChain' JSON structure you should send Block's related data:
- Type (Noda)
- Block :
  - Index     
  - Timestamp 
  - PubKey    
  - Data      
  - Hash      
  - PrevHash  

> Example of JSON Structure:

```
{"Type":"Noda",
"Data":"Will be passed at Noda's mode",
"BlockData":{"Index":3,
"Timestamp":"Will be passed at Client's mode",
"PubKey":"-----BEGIN RSA PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxNHEyAqbSzPVXI26VNXC\nHApXYrWhoLcrEVm7iDVaPQZ1W5cLLp9ZrKH1CrO3L32Z3OS0ZugEe72ofjzWrxfA\nFg0GXxwIta+QcattynCeaw1USBfaKAyZf1+tjXfZ7bmL7Ux/faTkMxQU+1K3XVGW\nhuoqvuW6OXw4pyABHlD7uHRZOSuYpTAaOu8W5ukPMXxo/GyJaWZa8A06v9Eg6sfx\njA7RoanZgxknfctWIHygUhC6NrjfcBjpzeAh9pKleLJf/UEqpZACisdPQP5Sel/F\nTaQl58eJskp0S7ggD+6M1tWUu2FXHIr6avzfVLWKYEqdmxPzNCMSOnBiDfLSuCLq\ntWvHr29Z1fF/S2zW3sBbWBcIQ7600MgzoZWvhw0ZhaMaJnuwb1G9oW0r3XUMuZPQ\nruEMef8b6p82ZUH2hS9VEhSk0ReNZ9Jqnj+Foa7XS7Er8TGQmtmgYsDV/qj+AF+J\ntNCSrazvHFyOKCMwz9KGtjGgzKgA7y+Gg33HnyUJlDP2uT6uZazVKzqF3j5tx06/\njxqmO3MNJiZ/LXwh3v+xB/U9yj3waDZ7Wsw+ZvjC3L/prsJaMGiyMm1zRGNSW47V\nIC6LJVF2XX/j8unjGbZymTmXyD3rZL4NCAbOfkYYHH7C+B8SnetglcrSQhegTV++\nFHYe+7OQkKLPt1FjALNEdSsCAwEAAQ==\n-----END RSA PUBLIC KEY-----\n",
"Data":"Stored Data",
"Hash":"Block SHA256 Hash",
"PrevHash":"Prev block SHA256 Hash"}}
```




