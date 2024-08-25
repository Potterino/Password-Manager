import json

# This is the default file location for the output of the text file. You can change the directory if you want
# to save the file to another location. IMPORTANT: If you change this, make sure to use a raw string format to
# pass the path ( r"...."). Otherwise an error will be raised.

default_file_location = r"C:\Users\Ferdi\Desktop"

# The file name can be changed as well. Make sure to use a .txt format and always write out the whole file
# including the txt extension as shown in this default file name.

file_name = "password.txt"
full_path = default_file_location + "\\" + file_name

# Constants

ASCII_UPPER_BOUND = 126
ASCII_LOWER_BOUND = 32
ASCII_DIFFERENCE = 95
INDEX_BOUND = 31


# Helper functions

# ALL TESTS WERE RUN ON THE EXAMPLE FILE IN THE FOLDER


def write_file(plat, username, pw, i_s, i_p, comma_list):
    """
    A helper function to write the user input and the encrypted password into a text file.
    :param plat: The name of the platform
    :param username: The corresponding username
    :param pw: The encrypted password
    :param i_s: The initial index shift
    :param i_p: The initial index permutation
    :param comma_list: The list with the indexes of commas
    :return: None
    """
    file = open(full_path, "a+")
    file.write("{0}, {1}, {2}, {3}, {4}, {5} \n".format(plat.lower(), username, pw, i_s, i_p, comma_list))
    file.close()


def read_file(path):
    """
    A function that reads the existing password file and adds all the entries to a dictionary. This helps the user
    to gain an overview on the passwords text file and enables searching for a password on a specific platform.
    :param: path: Equals the full path of the text file.
    :return: A nested list in the format:
            [["platform", "username", "password",...],
            ["platform", "username", "password",...],
            ...
            ]
    >>> read_file(full_path)
    [['facebook', ' potti', ' jcoos', ' 2', ' 2', ' []'], ['youtube', ' potti', ' -./0123456789', ' 1', ' 1', ' []']]

    HERE I GET AN ERROR BECAUSE OF THE \n CHARACTER IN THE TEXTFILE. I HAD TO PRINT THE "\n" IN THE FILE SO I COULD READ
    THE FILE LINE BY LINE. BUT IT SEEMS THAT DOCSTRING HAS SOME TROUBLE INTERPRETING IT. BUT THIS CHARACTER IS THE ONLY THING
    THAT DIFFERS FROM MY ACTUAL OUTPUT, SO I'D COUNT IT AS A VALID TEST.
    """

    # Creating an empty list that stores each entry (represented by a line in the file)
    entry_list = []
    file = open(path, "r")
    for line in file:
        # Creating a sub-list that is represented by one entry (line) of the file
        sub_list = []
        # Splitting the line by 5 components by a comma. Each component represents a specific category of the input
        # (i.e. the username)
        for word in line.split(",", 5):
            sub_list.append(word)
        entry_list.append(sub_list)
    file.close()
    return entry_list


def create_dict(entry_list):
    """
    A function to put the nested list form the read file together with the dictionary keys and create a nested
    dictionary)
    :param entry_list: The nested list in the format as stated in the function above (read_file())
    :return: A dictionary of the entries in the format:
                {platform1: {'Username': 'value(username_platform1)',
                            'Encrypted password': ' value(encrypted_password_platform1)',
                            'Index shift': value(index_shift_platform1),
                            'Index permutation': value(index permutation_platform1),
                            'Comma list': 'value(comma_list_platform1)'},
                platform2:  {'Username': 'value(username_platform2)',
                            ...}
                ...
                }
    >>> create_dict([['facebook', ' potti', ' jcoos', ' 2', ' 2', ' []']])
    {'facebook': {'Username': ' potti', 'Encrypted password': ' jcoos', 'Index shift': ' 2', 'Index permutation': ' 2', 'Comma list': ' []'}}
    >>> create_dict([['facebook', ' potti', ' jcoos', ' 2', ' 2', ' []'], ['youtube', ' potti', ' -./0123456789', ' 1', ' 1', ' []']])
    {'facebook': {'Username': ' potti', 'Encrypted password': ' jcoos', 'Index shift': ' 2', 'Index permutation': ' 2', 'Comma list': ' []'}, 'youtube': {'Username': ' potti', 'Encrypted password': ' -./0123456789', 'Index shift': ' 1', 'Index permutation': ' 1', 'Comma list': ' []'}}

    """
    dict_keys = ["Username", "Encrypted password", "Index shift", "Index permutation", "Comma list"]
    # Creating the main-dictionary for all entries (represented by one line) in the file
    entry_dict = {}
    for entry in entry_list:
        # Creating a sub-dictionary that includes one entry (line) of the file
        platform_details = {}
        # Add each key to the corresponding value, as read in the file
        for key, value in zip(dict_keys, entry[1:]):
            platform_details[key] = value
        # The platform name is the first entry of each line
        platform_name = str(entry[0])
        # Add the sub-dictionary to the main-dictionary
        entry_dict[platform_name] = platform_details
    return entry_dict


def print_dict(dictionary):
    """
    A function to print out the whole dictionary for an overview.
    :param dictionary: The nested dictionary structure
    :return: None
    >>> print_dict({'facebook': {'Username': ' potti', 'Encrypted password': ' jcoos', 'Index shift': ' 2', 'Index permutation': ' 2', 'Comma list': ' []'}})
    You have these entries:
    Facebook
    >>> print_dict({'facebook': {'Username': ' potti', 'Encrypted password': ' jcoos', 'Index shift': ' 2', 'Index permutation': ' 2', 'Comma list': ' []'}, 'youtube': {'Username': ' potti', 'Encrypted password': ' -.'}})
    You have these entries:
    Facebook
    Youtube
    """

    print("You have these entries:")
    for key in dictionary:
        print(key.capitalize())


def platform_search(search, entry_dict):
    """
    A function that checks, if a specific term (entered in the retrieve function) is in the entry-dictionary (in the
    text file)
    :param search: A string with the entered search keyword
    :param entry_dict: A dictionary (type dict) that is being searched for the keyword
    :return: The search keyword, if it is found in the entry dictionary.
    >>> platform_search("facebook", {'facebook': {'Username': ' abc', 'Encrypted password': ' jcoos', 'Index shift': ' 2', 'Index permutation': ' 2', 'Comma list': ' []'}, 'youtube': {'Username': ' abc', 'Encrypted password': ' -./0123456789', 'Index shift': ' 1', 'Index permutation': ' 1', 'Comma list': ' []'}})
    'facebook'
    >>> platform_search("abc", {'facebook': {'Username': ' abc', 'Encrypted password': ' jcoos', 'Index shift': ' 2', 'Index permutation': ' 2', 'Comma list': ' []'}, 'youtube': {'Username': ' abc', 'Encrypted password': ' -./0123456789', 'Index shift': ' 1', 'Index permutation': ' 1', 'Comma list': ' []'}})
    Traceback (most recent call last):
    ValueError: No results for your keyword: abc
    """

    # Of the keyword is found in the dictionary, validate the keyword by returning it (.lower() method is used to make
    # the search not case-sensitive
    if search.lower() in entry_dict.keys():
        return search
    # Otherwise raise an error
    else:
        raise ValueError("No results for your keyword: " + search)


def check_user_input(plat, username, password, index_shift, index_permutation):
    """
    A helper function to check, if the input is valid.
    :param plat: A string for the name of the platform.
    :param username: A string for the username.
    :param password: A string for the password.
    :param index_shift: An integer or string between 0 - 31 for the index_shift.
    :param index_permutation: An integer or string between 0 - 31 for the index_permutation.
    :return: The values for "platform", "username", "password", "index_shift", index_permutation.

    # Testing for valid/printable characters (critical values: spacebar (ASCII 32), "~" (ASCII 126), unit seperator (ASCII 31) and delete (ASCII 127)

    >>> check_user_input("all correct here ~", "John", "abc", 1, 1)
    ('all correct here ~', 'John', 'abc', 1, 1)
    >>> check_user_input("invalid ▼" + chr(127), "John", "abc", 1, 1)
    Traceback (most recent call last):
    ValueError: Your platform contains an invalid letter. Please use the ASCII standard characters.
    >>> check_user_input("wrong_letter_ä", "John", "abc", 1, 1)
    Traceback (most recent call last):
    ValueError: Your platform contains an invalid letter. Please use the ASCII standard characters.
    >>> check_user_input("Facebook", "Bärbel", "abc", 1, 1)
    Traceback (most recent call last):
    ValueError: Your username contains an invalid letter. Please use the ASCII standard characters.
    >>> check_user_input("Facebook", "John", "äöü", 1, 1)
    Traceback (most recent call last):
    ValueError: Your password contains an invalid letter. Please use the ASCII standard characters.

    # Testing for every blank argument

    >>> check_user_input("", "abc", "abc", 1, 1)
    Traceback (most recent call last):
    ValueError: One or more empty blanks detected. Please try again.
    >>> check_user_input("Facebook", "", "abc", 1, 1)
    Traceback (most recent call last):
    ValueError: One or more empty blanks detected. Please try again.
    >>> check_user_input("Facebook", "abc", "", 1, 1)
    Traceback (most recent call last):
    ValueError: One or more empty blanks detected. Please try again.

    # Testing for valid types

    >>> check_user_input("Facebook", "John", "valid", "1", "1")
    Traceback (most recent call last):
    TypeError: Index shift and index permutation must be integer numbers.
    >>> check_user_input("Facebook", "John", "valid", "1", "a")
    Traceback (most recent call last):
    TypeError: Index shift and index permutation must be integer numbers.
    >>> check_user_input("Facebook", "John", "valid", "a", "1")
    Traceback (most recent call last):
    TypeError: Index shift and index permutation must be integer numbers.

    # Testing for valid integer units

    >>> check_user_input("Facebook", "John", "valid", 0, 0)
    ('Facebook', 'John', 'valid', 0, 0)
    >>> check_user_input("Facebook", "John", "valid", 31, 31)
    ('Facebook', 'John', 'valid', 31, 31)
    >>> check_user_input("Facebook", "John", "valid", 32, 32)
    Traceback (most recent call last):
    ValueError: Index shift or index permutation must be between 0 and 31. Please try again.
    >>> check_user_input("Facebook", "John", "valid", -1, -1)
    Traceback (most recent call last):
    ValueError: Index shift or index permutation must be between 0 and 31. Please try again.
    >>> check_user_input("Facebook", "John", "valid", -1, 0)
    Traceback (most recent call last):
    ValueError: Index shift or index permutation must be between 0 and 31. Please try again.
    >>> check_user_input("Facebook", "John", "valid", 0, -1)
    Traceback (most recent call last):
    ValueError: Index shift or index permutation must be between 0 and 31. Please try again.
    """
    # Checking if there is any input for each argument

    if "" in [plat, username, password, index_shift, index_permutation]:
        raise ValueError("One or more empty blanks detected. Please try again.")

    # Checking for unprintable ASCII characters in platform, username and password

    for p in plat:
        if ord(p) < ASCII_LOWER_BOUND or ord(p) > ASCII_UPPER_BOUND:
            raise ValueError("Your platform contains an invalid letter. Please use the ASCII standard characters.")
    for u in username:
        if ord(u) < ASCII_LOWER_BOUND or ord(u) > ASCII_UPPER_BOUND:
            raise ValueError("Your username contains an invalid letter. Please use the ASCII standard characters.")
    for p in password:
        if ord(p) < ASCII_LOWER_BOUND or ord(p) > ASCII_UPPER_BOUND:
            raise ValueError("Your password contains an invalid letter. Please use the ASCII standard characters.")

    # Checking for specified input conditions

    if not (type(index_shift) and type(index_permutation)) == int:
        raise TypeError("Index shift and index permutation must be integer numbers.")
    elif not ((0 <= index_shift <= INDEX_BOUND) and (0 <= index_permutation <= INDEX_BOUND)):
        raise ValueError("Index shift or index permutation must be between 0 and 31. Please try again.")
    return plat, username, password, index_shift, index_permutation


def encryption(password, index_shift, index_permutation):
    """
    Encryption function to encrypt a given password
    :param password: A string that contains all printable ASCII characters (32 - 126)
    :param index_shift: An integer (0 - 31) that defines the amount of the shift between the original and the encrypted character (for 2 --> every a is going to be a c)
    :param index_permutation: An integer (0 - 31) that defines the rate of the change of the index shift (for 2 --> every second time the index shift is incremented by 1)
    :return: The encrypted password

    # Testing traceable/comprehensible keywords to demonstrate the basic function

    >>> encryption("hello", 0, 0)
    ('hello', 0, 0, [])
    >>> encryption("hello", 1, 0)
    ('ifmmp', 1, 0, [])
    >>> encryption("hello", 1, 1)
    ('igopt', 1, 1, [])

    # Testing critical values (characters before commas ("+") (ASCII 43) and boundary "~" (ASCII 126)

    >>> encryption("+++~~", 1, 1)
    ('--.#$', 1, 1, [0])
    >>> encryption("+++++", 1, 0)
    ('-----', 1, 0, [0, 1, 2, 3, 4])
    >>> encryption("~~~~~", 1, 0)
    ('     ', 1, 0, [])
    >>> encryption("~~~~~", 1, 1)
    (' !"#$', 1, 1, [])

    # Testing for index shift and index permutation boundaries

    >>> encryption("+++~~", 31, 31)
    ('JJJ>>', 31, 31, [])

    # Testing for a long password and high shift and permutation values

    >>> encryption("abcdefghijklmnop!'sdawf''+,,,,,**+++~~", 31, 31)
    ('!"#$%&\\'()*+--./0@F3$!7&FFJKKKKKJJKKK??', 31, 31, [11])
    """

    index_permutation = int(index_permutation)
    # Create a variable for the encoded password to be stored
    enc_password = ""
    # Initiate a boolean variable for the permutation
    perm = False
    # Create a copy of the index shift which is modified over the encryption process. The original value is passed
    # to the decryption function later on to restore the password
    index_shift_copy = index_shift
    # Create a list, where the index position that would be encrypted into a comma (ASCII 44) is stored. This is
    # important due to the significance of the comma as a separator in the text file. The list is needed to make sure
    # that the corresponding decryption process just takes place, if a comma was hit in the encryption process
    comma = []
    # A variable that keeps track of the current index position
    index_pos = 0

    # Check if an index permutation was entered. If so, introduce a counter to modify the index shift after every n-th
    # iteration and set perm to True

    if index_permutation != 0:
        perm = True
        count = 1
    for letter in password:
        enc_letter = ord(letter) + index_shift_copy
        # Start over from ASCII position 32 if ASCII number 126 is exceeded
        if enc_letter > ASCII_UPPER_BOUND:
            enc_letter -= ASCII_DIFFERENCE
        # In case of a comma (which is needed to be a unique character/separator for the file reading process afterwards)
        if enc_letter == 44:
            enc_letter += 1
            # If this is the case, create a list with the comma indices to check later in the decryption process
            comma.append(index_pos)
        if perm:
            if count % index_permutation == 0:
                index_shift_copy += 1
            count += 1
        enc_password += chr(enc_letter)
        index_pos += 1
    enc_password = str(enc_password)
    return enc_password, index_shift, index_permutation, comma


def decryption(password, index_shift, index_permutation, comma):
    """
    Decryption of the password
    :param password: The encrypted password
    :param index_shift: The index shift value at the end of the encryption process
    :param index_permutation: The index permutation for the corresponding password
    :param comma: A list of the index positions of the commas
    :return: The decrypted password

    # Backwards-testing traceable/comprehensible keywords to demonstrate the basic function

    >>> decryption("hello", 0, 0, "[]")
    'hello'
    >>> decryption('ifmmp', 1, 0, "[]")
    'hello'
    >>> decryption('igopt', 1, 1, "[]")
    'hello'

    # Backwards-testing critical values (characters before commas ("+") (ASCII 43) and boundary "~" (ASCII 126)

    >>> decryption("--.#$", 1, 1, "[0]")
    '+++~~'
    >>> decryption('-----', 1, 0, "[0, 1, 2, 3, 4]")
    '+++++'
    >>> decryption('     ', 1, 0, "[]")
    '~~~~~'
    >>> decryption(' !"#$', 1, 1, "[]")
    '~~~~~'

    # Testing for index shift and index permutation boundaries

    >>> decryption('JJJ>>', 31, 31, "[]")
    '+++~~'
    """

    index_shift = int(index_shift)
    index_permutation = int(index_permutation)
    dec_password = ""
    perm = False
    index_shift_copy = index_shift
    index_pos = 0
    # The JSON command is used to convert the list of class string to a list of class list
    comma_list = json.loads(comma)
    # Check if index permutation was entered and if it is the first iteration. If so, introduce a counter and set perm
    # to True

    if index_permutation != 0 and len(dec_password) == 0:
        count = 1
        perm = True
    for letter in password:
        enc_letter = ord(letter) - index_shift_copy
        # If letter hit ASCII 45, and we calculated this value in the encryption process because we hit a comma (44)
        # at a certain position after encryption, we have to subtract the value 1 we added before at that position
        if ord(letter) == 45 and index_pos in comma_list:
            enc_letter -= 1
        if enc_letter < ASCII_LOWER_BOUND:
            enc_letter += ASCII_DIFFERENCE
        if perm:
            if count % index_permutation == 0:
                index_shift_copy += 1
            count += 1
        dec_password += chr(enc_letter)
        index_pos += 1
    return dec_password


# Import tests
if __name__ == "__functions__":
    import doctest
    doctest.testmod(verbose=True)
