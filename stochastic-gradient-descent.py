import time
import random
import pickle
import threading
import seal
from seal import ChooserEvaluator, \
    Ciphertext, \
    Decryptor, \
    Encryptor, \
    EncryptionParameters, \
    Evaluator, \
    IntegerEncoder, \
    FractionalEncoder, \
    KeyGenerator, \
    MemoryPoolHandle, \
    Plaintext, \
    SEALContext, \
    EvaluationKeys, \
    GaloisKeys, \
    PolyCRTBuilder, \
    ChooserEncoder, \
    ChooserEvaluator, \
    ChooserPoly

def updateM(evaluator, m_e_current, x_e_data, learningRate_e, delta_e):
    evaluator.multiply(x_e_data, learningRate_e)
    evaluator.multiply(x_e_data, delta_e)
    evaluator.negate(x_e_data)
    evaluator.add(m_e_current, x_e_data)
    return m_e_current

def updateB(evaluator, b_e_current, learningRate_e, delta_e):
    evaluator.multiply(delta_e,learningRate_e)
    evaluator.negate(delta_e)
    evaluator.add(b_e_current, delta_e)
    return b_e_current

def learn(y_data,x_data, evaluator, m_data, b_data, encoder, encryptor, learningRate_e, decryptor):
    y_data_encoded = encoder.encode(y_data)
    x_data_encoded = encoder.encode(x_data)
    m_data_encoded = encoder.encode(m_data)
    b_data_encoded = encoder.encode(b_data)

    # Encrypting the values is easy.
    y_e_data = Ciphertext()
    x_e_data = Ciphertext()
    encryptor.encrypt(y_data_encoded, y_e_data)
    encryptor.encrypt(x_data_encoded, x_e_data)

    m_e_current = Ciphertext()
    b_e_current = Ciphertext()

    encryptor.encrypt(m_data_encoded, m_e_current)
    encryptor.encrypt(b_data_encoded, b_e_current)

    # Calculate y_e_predicted = m_e_c*x_e_data _ b_e_c
    ypred_data = 1.0
    ypred_data_encoded = encoder.encode(ypred_data)
    ypred_e_data = Ciphertext()
    encryptor.encrypt(ypred_data_encoded, ypred_e_data)
    evaluator.multiply(ypred_e_data, x_e_data)
    evaluator.multiply(ypred_e_data, m_e_current)
    evaluator.add(ypred_e_data, b_e_current)

    # delta = ypred_e - y_e
    evaluator.negate(y_e_data)
    evaluator.add(ypred_e_data, y_e_data)

    # Update m and b
    m_e_current = updateM(evaluator, m_e_current, x_e_data, learningRate_e, ypred_e_data)
    b_e_current = updateB(evaluator, b_e_current, learningRate_e, ypred_e_data)
    
    retVals = []
    m_learnt = Plaintext()
    decryptor.decrypt(m_e_current, m_learnt)
    retVals.append(encoder.decode(m_learnt))
    b_learnt = Plaintext()
    decryptor.decrypt(b_e_current, b_learnt)
    retVals.append(encoder.decode(b_learnt))

    return retVals

def unit_test():
    parms = EncryptionParameters()
    parms.set_poly_modulus("1x^8192 + 1")
    parms.set_coeff_modulus(seal.coeff_modulus_128(8192))
    parms.set_plain_modulus(1 << 10)
    context = SEALContext(parms)

    # Print the parameters that we have chosen
    print_parameters(context);
    encoder = FractionalEncoder(context.plain_modulus(), context.poly_modulus(), 64, 32, 3)
    keygen = KeyGenerator(context)
    public_key = keygen.public_key()
    secret_key = keygen.secret_key()
    encryptor = Encryptor(context, public_key)

    # Computations on the ciphertexts are performed with the Evaluator class.
    evaluator = Evaluator(context)

    # We will of course want to decrypt our results to verify that everything worked,
    # so we need to also construct an instance of Decryptor. Note that the Decryptor
    # requires the secret key.

    decryptor = Decryptor(context, secret_key)
    learningRate = 0.1
    learningRate_data = encoder.encode(learningRate);
    learningRate_e = Ciphertext()
    encryptor.encrypt(learningRate_data, learningRate_e)

    updatedVals = []
    updatedVals.append(50)
    updatedVals.append(50)
    updatedVals_unenc = []

    updatedVals_unenc.append(updatedVals[0])
    updatedVals_unenc.append(updatedVals[1])

    for i in range(15):
        x = 1
        y = 1
        updatedVals = learn(x,y,evaluator, updatedVals[0], updatedVals[1], encoder, encryptor,learningRate_e, decryptor)
        ypred = updatedVals_unenc[0]*x + updatedVals_unenc[1]
        error = ypred - y
        updatedVals_unenc[0] = updatedVals_unenc[0] - x*error*learningRate
        updatedVals_unenc[1] = updatedVals_unenc[1] - error*learningRate
        print((str)(updatedVals[1]) + ":" + (str)(updatedVals[0]) + ":" + (str)(updatedVals_unenc[1]) + ":" + (str)(updatedVals_unenc[0]))

        x = 2
        y = 3
        updatedVals = learn(x,y,evaluator, updatedVals[0], updatedVals[1], encoder, encryptor,learningRate_e, decryptor)
        ypred = updatedVals_unenc[0]*x + updatedVals_unenc[1]
        error = ypred - y
        updatedVals_unenc[0] = updatedVals_unenc[0] - x*error*learningRate
        updatedVals_unenc[1] = updatedVals_unenc[1] - error*learningRate
        print((str)(updatedVals[1]) + ":" + (str)(updatedVals[0]) + ":" + (str)(updatedVals_unenc[1]) + ":" + (str)(updatedVals_unenc[0]))

        x = 4
        y = 3
        updatedVals = learn(x,y,evaluator, updatedVals[0], updatedVals[1], encoder, encryptor,learningRate_e, decryptor)
        ypred = updatedVals_unenc[0]*x + updatedVals_unenc[1]
        error = ypred - y
        updatedVals_unenc[0] = updatedVals_unenc[0] - x*error*learningRate
        updatedVals_unenc[1] = updatedVals_unenc[1] - error*learningRate
        print((str)(updatedVals[1]) + ":" + (str)(updatedVals[0]) + ":" + (str)(updatedVals_unenc[1]) + ":" + (str)(updatedVals_unenc[0]))

        x = 3
        y = 2
        updatedVals = learn(x,y,evaluator, updatedVals[0], updatedVals[1], encoder, encryptor,learningRate_e, decryptor)
        ypred = updatedVals_unenc[0]*x + updatedVals_unenc[1]
        error = ypred - y
        updatedVals_unenc[0] = updatedVals_unenc[0] - x*error*learningRate
        updatedVals_unenc[1] = updatedVals_unenc[1] - error*learningRate
        print((str)(updatedVals[1]) + ":" + (str)(updatedVals[0]) + ":" + (str)(updatedVals_unenc[1]) + ":" + (str)(updatedVals_unenc[0]))

        x = 5
        y = 5
        updatedVals = learn(x,y,evaluator, updatedVals[0], updatedVals[1], encoder, encryptor,learningRate_e, decryptor)
        ypred = updatedVals_unenc[0]*x + updatedVals_unenc[1]
        error = ypred - y
        updatedVals_unenc[0] = updatedVals_unenc[0] - x*error*learningRate
        updatedVals_unenc[1] = updatedVals_unenc[1] - error*learningRate
        print((str)(updatedVals[1]) + ":" + (str)(updatedVals[0]) + ":" + (str)(updatedVals_unenc[1]) + ":" + (str)(updatedVals_unenc[0]))

def main():
    unit_test()

def print_parameters(context):
    print("/ Encryption parameters:")
    print("| poly_modulus: " + context.poly_modulus().to_string())
    # Print the size of the true (product) coefficient modulus
    print("| coeff_modulus_size: " + (str)(context.total_coeff_modulus().significant_bit_count()) + " bits")
    print("| plain_modulus: " + (str)(context.plain_modulus().value()))
    print("| noise_standard_deviation: " + (str)(context.noise_standard_deviation()))

if __name__ == '__main__':
    main()
