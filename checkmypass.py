# almost like a browser. Enables us to request something and get data back.
# In this case we will use requests with password API
import requests

# enables us to perfom sha-1 hashing
import hashlib

import sys


# function to request data and receive response.
def request_api_data(qury_char):

    # api uses k aninymity. Allows someone to receive info about us but not know who we are.
    # it works by only accepting the first 5 chars of our hashe password (SHA1)
    url = 'https://api.pwnedpasswords.com/range/' + qury_char

    response = requests.get(url)

    # if output is response 400 it usually means there is an authorisation issue or problem with API.
    if response.status_code != 200:
        raise RuntimeError(f'Error fetching: {response.status_code}. Check the API and try again')
    return response


def get_password_leak_count(hashes, hash_to_check):
    # using a tuple comprehension
    # split everything in the line where a ':' appears.
    # need to use splitlines() which breaks at line boundaries
    hashes = (line.split(':') for line in hashes.text.splitlines())

    # as we have converted to a tuple, we have the hash and the hash count
    for h, count in hashes:
        # checking if the tail of hash is equal to remaining_char as API returned to us a list of tailed hashes
        if h == hash_to_check:
            return count
    return 0


# check if password exits in API response.
def pwned_api_check(password):
    # hash our password
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

    # we need to store the first 5 chars of hashed password to work with API.
    # We also need to store the remaining chars of hashed password
    first5_char, remaining_char = sha1_password[:5], sha1_password[5:]

    # now we can added this to request_api_data
    response = request_api_data(first5_char)

    print(response)

    # hash_to_check will be remaining_char
    return get_password_leak_count(response, remaining_char)


# main function receives arguments which are the passwords we want to check.
def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times. You should change your password.')
        else:
            print(f'{password} was not found.')
        return 'done'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
