import secrets
import string


def generate(length:int) -> str:
    '''
    randomly generates a password with minimum length 12 characters

    :param length: the length of the desired password
    :type length: int
    :raise ValueError: if the provided length is less than 12
    :return: the generated shuffled password
    :rtype: str
    '''
    ## minimum iteration, and minimum length
    MIN_IT = 3
    MIN_LEN = 12 

    if length < 12:
        raise ValueError(f"Minimum length is {MIN_LEN}")
    
    required = ''
    ## randomly constructing minimum required chars(3 lowercase, 3 uppercase, 3 digits, and 3 special chars)
    for _ in range(MIN_IT):  
        required += (secrets.choice(string.ascii_lowercase) +
                    secrets.choice(string.ascii_uppercase) +
                    secrets.choice(string.digits) + secrets.choice(string.punctuation))
    
    ## create the pool and continue randomly constructing the remaining chars
    pool = string.ascii_letters + string.digits + string.punctuation 
    rest = ''.join(secrets.choice(pool) for _ in range(length - MIN_LEN))

    ## constructing the whole password and shuffelling it
    pswd = list(rest + required)
    secrets.SystemRandom().shuffle(pswd)

    return ''.join(pswd)
