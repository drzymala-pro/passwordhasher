# passwordhasher
Password hashing module for python.

This module has just three functions. The first one is for checking if the password is secure enough, which means that the password meets at least three of the following four criteria:
1. Password contains at least one uppercase character (A-Z)
2. Password contains at least one lowercase character (a-z)
3. Password contains at least one digit (0-9)
4. Password contains at least one special character (.,#$&*, etc.)

Additionaly:
1. Password must not contain more than two identical characters in a row, e.g. "aaa"
2. Password must not be less than 10 characters short
3. Password must not be more than 128 characters long

The module also provides an example function for generating password hashes, and a function to generate pseudo random hashing salt.

# Tutorial
## Check the password strength
``` python
from passwordhasher import is_password_secure

is_secure = is_password_secure('weak password')
```
## Create pseudo random salt for password hashing
``` python
from passwordhasher import create_random_password_salt

salt = create_random_password_salt()
```
## Get password hash
``` python
from passwordhasher import get_password_hash

stored_password_hash = ... # Get it from database
stored_password_salt = ... # Get it from database
entered_password = ... # Get the user entered password

computed_hash = get_password_hash(stored_password_salt, entered_password)

if computed_hash == stored_password_hash:
    # This user has provided the correct password.
    
```


