import os
import json
import functions
# This is the default file location for the output of the text file. You can change the directory if you want
# to save the file to another location. IMPORTANT: If you change this, make sure to use a raw string format to
# pass the path ( r"...."). Otherwise an error will be raised.

default_file_location = r"C:\Users\User"

# The file name can be changed as well. Make sure to use a .txt format and always write out the whole file
# including the txt extension as shown in this default file name.

file_name = "filename.txt"
full_path = default_file_location + "\\" + file_name


def get_add_retrieve_exit_input():
    """
    Asks the user, if he wants to add a new password to the existing file, or if he wants to read a password
    from an existing file.
    :return: The entered user input.
    """
    inp = input("Do you want to add (a) or retrieve (r) a password? Type (e) for exit.")
    return inp


def check_add_retrieve_exit(inp):
    """
    Checks if the user input entered before is valid.
    :return: The input letter in lowercase if it's a, r or e. Otherwise print "Invalid input...".
    """

    if inp.lower() not in ("a", "r", "e"):
        print("Invalid input, please try again.")
        return None
    return inp.lower()


def check_file():
    """
    Checks if file already exists.
    :return: True if file already exists, False if it needs to be created.
    """
    return os.path.isfile(full_path)


def size_of_file():
    return os.path.getsize(full_path)


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
    file.write("{0}, {1}, {2}, {3}, {4}, {5}\n".format(plat, username, pw, i_s, i_p, comma_list))
    file.close()


def read_file():
    """
    A function that reads the existing password file and adds all the entries to a dictionary. This helps the user
    to gain an overview on the passwords text file and enables searching for a password on a specific platform.
    :return: A nested dictionary in the format:
            {platform: {"username": username,
                        "password": password, ...}
    """
    file = open(full_path, "r")
    # Creating a list with the different keys
    dict_keys = ["Username", "Encrypted password", "Index shift", "Index permutation", "Comma list"]
    # Creating the main-dictionary for all entries (represented by one lines) in the file
    platform = {}
    # Loop through each line in the file
    for line in file:
        # Creating a sub-dictionary that includes one entry (line) of the file
        platform_details = {}
        # Add each key to the corresponding value, as read in the file
        for key, word in zip(dict_keys, line.split(",", 5)[1:]):
            platform_details[key] = word
        # The platform name is the first entry of each line
        platform_name = str(line.split(",")[0])
        # Add the sub-dictionary to the main-dictionary
        platform[platform_name] = platform_details
    return platform


def print_dict(dictionary):
    """
    A function to print out the whole dictionary for an overview.
    :param dictionary: The nested dictionary structure
    :return: None
    """
    print("You have these entries: ")
    for key in dictionary:
        print(key)


def platform_search(search):
    if search in platform_dict.keys():
        return search
    else:
        print("No results for you keyword: " + search)
        print("Please try again.")
        return False


def get_user_input():

    plat = input("Please enter your platform/website/service: ")
    username = input("Please enter your username/e-mail address etc.: ")
    password = input("Please enter your password: ")
    index_shift = input("Please enter the number of index shifts per letter (0 - 31): ")
    index_permutation = input("Please enter the permutation factor of the index shift (0 - 31): ")
    return plat, username, password, index_shift, index_permutation


def check_user_input(plat, username, password, index_shift, index_permutation):
    """
    Asks the user for an input.
    :return: The values for "platform", "username", "password", "index_shift", index_permutation.
    """

    # Checking for unprintable ASCII characters in platform, username and password

    for p in plat:
        if ord(p) < 30 or ord(p) > 126:
            raise ValueError("Your platform contains an invalid letter. Please use the ASCII standard characters.")
    for u in username:
        if ord(u) < 30 or ord(u) > 126:
            raise ValueError("Your username contains an invalid letter. Please use the ASCII standard characters.")
    for p in password:
        if ord(p) < 30 or ord(p) > 126:
            raise ValueError("Your password contains an invalid letter. Please use the ASCII standard characters.")

    # Checking for specified input conditions

    try:
        index_shift = int(index_shift)
        index_permutation = int(index_permutation)
    except ValueError:
        raise ValueError("Index shift and index permutation must be integer numbers.")
    if (password or plat or username or index_shift or index_permutation) == "":
        raise ValueError("One or more empty blanks detected. Please try again.")
    elif not (type(index_shift) and type(index_permutation)) == int:
        raise TypeError("Index shift and index permutation must be integer numbers.")
    elif not ((0 <= index_shift <= 31) and (0 <= index_permutation <= 31)):
        raise ValueError("Index shift or index permutation must be between 0 and 31. Please try again.")
    print("Is this your password for " + plat + ": " + password + "? Is this you username for " + plat + " " + username + "?")
    inp = input("Confirm with enter. To correct your input, type anything.")
    if inp == "":
        return plat.lower(), username.lower(), password, index_shift, index_permutation
    else:
        get_user_input()


def encryption(password, index_shift, index_permutation):
    """
    Encryption function to encrypt a given password
    :param password: A string that contains all printable ASCII characters (32 - 126)
    :param index_shift: An integer (0 - 31) that defines the amount of the shift between the original and the encrypted character (for 2 --> every a is going to be a c)
    :param index_permutation: An integer (0 - 31) that defines the rate of the change of the index shift (for 2 --> every second time the index shift is incremented by 1)
    :return: The encrypted password
    >>> encryption("hello", 1, 0)
    ('ifmmp', 1, 0, [])
    >>> encryption("hello", 1, 1)
    ('igopt', 1, 1, [])
    """
    index_permutation = int(index_permutation)
    # Create a variable for the encoded password to be stored
    enc_password = ""
    # Initiate a boolean variable for the permutation
    perm = False
    # Create a copy of the index shift which is modified over the encryption process. The original value is passed
    # to the decryption function later on to restore the password
    index_shift_copy = int(index_shift)
    # Create a list, where the index position that would be encrypted into a comma (ASCII 44) is stored. This is
    # important due to the significance of the comma as a separator in the text file. The list is needed to make sure
    # that the corresponding decryption process just takes place, if a comma was hit in the encryption process
    comma_list = []
    # A variable that keeps track of the current index position
    index_pos = 0

    # Check if an index permutation was entered. If so, introduce a counter to modify the index shift after every n-th
    # iteration and set perm to True

    if index_permutation != 0:
        count = 1
        perm = True
    for letter in password:
        enc_letter = ord(letter) + index_shift_copy
        if enc_letter == 44:
            enc_letter += 1
            # If this is the case, create a list with th comma indices to check later in the decryption process
            comma_list.append(index_pos)
        # Start over from ASCII position 32 if ASCII number 126 is exceeded
        if enc_letter > 126:
            enc_letter -= 95
        # In case of a comma (which is needed to be a unique character/separator for the file reading process afterwards)
        if perm:
            if count % index_permutation == 0:
                index_shift_copy += 1
            count += 1
        enc_password += chr(enc_letter)
        index_pos += 1
    enc_password = str(enc_password)
    return enc_password, index_shift, index_permutation, comma_list


def decryption(password, index_shift, index_permutation, comma_list):
    """
    Decryption of the password
    :param password: The encrypted password
    :param index_shift: The index shift value at the end of the encryption process
    :param index_permutation: The index permutation for the corresponding password
    :return: The decrypted password
    """

    index_shift = int(index_shift)
    index_permutation = int(index_permutation)
    dec_password = ""
    perm = False
    index_shift_copy = index_shift
    index_pos = 0
    # The JSON command is used to convert the list of class string to a list of class list
    comma_list = json.loads(comma_list)
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
        if enc_letter < 32:
            enc_letter += 95
        if perm:
            if count % index_permutation == 0:
                index_shift_copy += 1
            count += 1
        dec_password += chr(enc_letter)
        index_pos += 1
    return dec_password


running = True
# create a new file if it doesn't exist yet
if not check_file():
    file = open(full_path, "w")
else:
    file = open(full_path, "a+")

i1 = None
while running is True:
    if i1 is None:
        i1 = get_add_retrieve_exit_input()
        i1 = check_add_retrieve_exit(i1)
    elif i1 == "a":
        platform, username, password, index_shift, index_permutation = get_user_input()
        check_user_input(platform, username, password, index_shift, index_permutation)
        password, index_shift, index_permutation, comma_list = encryption(password, index_shift, index_permutation)
        write_file(platform, username, password, index_shift, index_permutation, comma_list)
        i1 = None
    elif i1 == "r":
        if size_of_file() == 0:
            print("Your file doesn't contain any passwords yet.")
            i1 = None
        else:
            platform_dict = read_file()
            print_dict(platform_dict)
            search_term = input("The password of which platform do you want to retrieve? ")
            platform_search(search_term)
            password = platform_dict[search_term]["Encrypted password"].strip()
            index_shift = platform_dict[search_term]["Index shift"].strip()
            index_permutation = platform_dict[search_term]["Index permutation"].strip()
            username = platform_dict[search_term]["Username"].strip()
            comma_list = platform_dict[search_term]["Comma list"].strip()
            ret_password = decryption(password, index_shift, index_permutation, comma_list)
            print("Your password is: " + ret_password + ". Your username is: " + username)
            i1 = None
    elif i1 == "e":
        running = False
    else:
        i1 = get_add_retrieve_exit_input()
        i1 = check_add_retrieve_exit(i1)
