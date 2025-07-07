import java.util.ArrayList;
import java.util.Arrays; // Added for Arrays.asList()
import java.util.HashSet;
import java.util.List;
import java.util.Set;    // Added for Set interface

// Imports needed for main method testing
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.NoSuchAlgorithmException; // For KeyPairGenerator and Signature
import java.security.InvalidKeyException;    // For Signature
import java.security.SignatureException;     // For Signature


public class TxHandler {

    private UTXOPool utxoPool;

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        this.utxoPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool,
     * (2) the signatures on each input of {@code tx} are valid,
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        double sumInput = 0;
        double sumOutput = 0;
        HashSet<UTXO> claimedUTXOs = new HashSet<>();

        for (int i = 0; i < tx.numInputs(); i++) {
            Transaction.Input input = tx.getInput(i);

            // input.prevTxHash can be null for coinbase transactions, but UTXO constructor expects non-null.
            // This implies coinbase transactions are not handled by this logic and would fail here.
            // This is consistent with rule (1) if coinbase inputs are not in UTXOPool.
            if (input.prevTxHash == null) { // Explicitly handle or document this case if necessary
                return false; // Or throw an error, or handle coinbase tx differently
            }
            UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);

            // (1) all outputs claimed by tx are in the current UTXO pool
            // This check must come before accessing utxoPool.getTxOutput(utxo)
            if (!utxoPool.contains(utxo)) {
                return false;
            }

            Transaction.Output correspondingOutput = utxoPool.getTxOutput(utxo);
            // This check is technically redundant if utxoPool.contains(utxo) is true and utxoPool is consistent,
            // but doesn't hurt as a safeguard.
            if (correspondingOutput == null) {
                return false;
            }

            // (2) the signatures on each input of tx are valid
            PublicKey pk = correspondingOutput.address;
            byte[] message = tx.getRawDataToSign(i);
            byte[] signature = input.signature;
            if (signature == null || !Crypto.verifySignature(pk, message, signature)) {
                return false;
            }

            // (3) no UTXO is claimed multiple times by tx
            // Must check after utxo object is created and before adding to sumInput
            if (claimedUTXOs.contains(utxo)) {
                return false;
            }
            claimedUTXOs.add(utxo);

            sumInput += correspondingOutput.value;
        }

        for (Transaction.Output output : tx.getOutputs()) {
            // (4) all of tx's output values are non-negative
            if (output.value < 0) {
                return false;
            }
            sumOutput += output.value;
        }

        // (5) the sum of tx's input values is greater than or equal to the sum of its output values
        if (sumOutput > sumInput) {
            // Using a small epsilon for floating point comparison is good practice,
            // but for this assignment, direct comparison is usually assumed.
            // e.g. if (sumOutput > sumInput + EPSILON)
            return false;
        }

        return true;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        Set<Transaction> txsToProcess = new HashSet<>(Arrays.asList(possibleTxs));
        List<Transaction> acceptedTransactions = new ArrayList<>();
        boolean newTxAcceptedInPass;

        do {
            newTxAcceptedInPass = false;
            Set<Transaction> processedInThisPass = new HashSet<>();

            for (Transaction tx : txsToProcess) {
                if (isValidTx(tx)) { // isValidTx uses the current state of this.utxoPool
                    acceptedTransactions.add(tx);
                    processedInThisPass.add(tx);
                    newTxAcceptedInPass = true;

                    // Remove spent UTXOs from the pool
                    for (Transaction.Input input : tx.getInputs()) {
                        // Ensure prevTxHash is not null, similar to isValidTx.
                        // However, isValidTx should already catch this.
                        if (input.prevTxHash == null) continue; // Should not happen if isValidTx passed
                        UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
                        this.utxoPool.removeUTXO(utxo);
                    }

                    // Add new UTXOs (outputs of this transaction) to the pool
                    // Assumes tx.getHash() is available and correct (i.e., tx.finalize() was called)
                    byte[] txHash = tx.getHash();
                    if (txHash == null) {
                        // This would indicate an issue with the transaction object's state.
                        // For robustness, could skip or log, but problem implies tx are finalized.
                        // For now, assume txHash is valid if isValidTx passed (though it doesn't check hash directly).
                        // A transaction needs a hash to be part of a new UTXO.
                        // If tx.finalize() wasn't called, tx.getHash() might be null.
                        // Let's assume Transaction objects are properly finalized before being passed here.
                        // If not, tx.finalize() might need to be called here.
                    }

                    for (int i = 0; i < tx.numOutputs(); i++) {
                        Transaction.Output output = tx.getOutput(i);
                        UTXO newUtxo = new UTXO(txHash, i);
                        this.utxoPool.addUTXO(newUtxo, output);
                    }
                }
            }
            txsToProcess.removeAll(processedInThisPass);
            // If no new transactions were accepted in a full pass over remaining txs, stop.
        } while (newTxAcceptedInPass && !txsToProcess.isEmpty());

        return acceptedTransactions.toArray(new Transaction[acceptedTransactions.size()]);
    }

    @SuppressWarnings("deprecation") // To suppress warnings for Arrays.toString(byte[]) if any, though direct usage is fine.
    public static void main(String args[]) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Test Setup: KeyPairs and initial UTXOPool
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());

        KeyPair pair1 = keyGen.generateKeyPair();
        PrivateKey privateKey1 = pair1.getPrivate();
        PublicKey publicKey1 = pair1.getPublic();

        KeyPair pair2 = keyGen.generateKeyPair();
        PublicKey publicKey2 = pair2.getPublic();

        // Create an initial UTXO
        Transaction genesisTx = new Transaction();
        genesisTx.addOutput(10.0, publicKey1);
        genesisTx.finalize();

        UTXO utxo1 = new UTXO(genesisTx.getHash(), 0);
        UTXOPool initialPool = new UTXOPool();
        initialPool.addUTXO(utxo1, genesisTx.getOutput(0));

        System.out.println("Initial UTXO Pool: " + initialPool.getAllUTXO().size() + " UTXOs");
        System.out.println("UTXO1 Hash: " + Arrays.toString(utxo1.getTxHash()) + " index " + utxo1.getIndex());
        if (initialPool.contains(utxo1)) {
            System.out.println("Output value: " + initialPool.getTxOutput(utxo1).value + ", address hash: " + initialPool.getTxOutput(utxo1).address.hashCode());
        }


        // Test Case 1: Valid Transaction
        System.out.println("\n--- Test Case 1: Valid Transaction ---");
        TxHandler handler1 = new TxHandler(new UTXOPool(initialPool));
        Transaction tx1 = new Transaction();
        tx1.addInput(genesisTx.getHash(), 0);
        tx1.addOutput(7.0, publicKey2);
        tx1.addOutput(2.5, publicKey1);

        byte[] dataToSign1 = tx1.getRawDataToSign(0);
        Signature sigObj1 = Signature.getInstance("SHA256withRSA");
        sigObj1.initSign(privateKey1);
        sigObj1.update(dataToSign1);
        byte[] signature1 = sigObj1.sign();
        tx1.addSignature(signature1, 0);
        tx1.finalize();

        System.out.println("Tx1 isValid: " + handler1.isValidTx(tx1));
        Transaction[] acceptedTxs1 = handler1.handleTxs(new Transaction[]{tx1});
        System.out.println("Accepted Txs for Test Case 1: " + acceptedTxs1.length);
        if (acceptedTxs1.length > 0) {
            System.out.println("Tx1 Hash: " + Arrays.toString(acceptedTxs1[0].getHash()));
            UTXOPool poolAfterTx1 = handler1.utxoPool;
            System.out.println("Pool contains original UTXO1: " + poolAfterTx1.contains(utxo1));
            UTXO tx1_out0 = new UTXO(tx1.getHash(), 0);
            UTXO tx1_out1 = new UTXO(tx1.getHash(), 1);
            System.out.println("Pool contains Tx1_Out0: " + poolAfterTx1.contains(tx1_out0));
            System.out.println("Pool contains Tx1_Out1: " + poolAfterTx1.contains(tx1_out1));
             if(poolAfterTx1.contains(tx1_out0) && poolAfterTx1.getTxOutput(tx1_out0) != null) System.out.println("Tx1_Out0 value: " + poolAfterTx1.getTxOutput(tx1_out0).value);
             if(poolAfterTx1.contains(tx1_out1) && poolAfterTx1.getTxOutput(tx1_out1) != null) System.out.println("Tx1_Out1 value: " + poolAfterTx1.getTxOutput(tx1_out1).value);
        }

        // Test Case 2: Invalid Signature
        System.out.println("\n--- Test Case 2: Invalid Signature ---");
        TxHandler handler2 = new TxHandler(new UTXOPool(initialPool));
        Transaction tx2 = new Transaction();
        tx2.addInput(genesisTx.getHash(), 0);
        tx2.addOutput(5.0, publicKey2);
        KeyPair pair_rogue = keyGen.generateKeyPair();
        Signature sigObj2_bad = Signature.getInstance("SHA256withRSA");
        sigObj2_bad.initSign(pair_rogue.getPrivate());
        sigObj2_bad.update(tx2.getRawDataToSign(0));
        byte[] signature2_bad = sigObj2_bad.sign();
        tx2.addSignature(signature2_bad, 0);
        tx2.finalize();
        System.out.println("Tx2 isValid (bad signature): " + handler2.isValidTx(tx2));

        // Test Case 3: Input UTXO not in pool
        System.out.println("\n--- Test Case 3: Input UTXO not in pool ---");
        TxHandler handler3 = new TxHandler(new UTXOPool(initialPool));
        Transaction tx3 = new Transaction();
        byte[] fakeTxHash = "fakehash".getBytes();
        tx3.addInput(fakeTxHash, 0);
        tx3.addOutput(1.0, publicKey2);
        byte[] dataToSign3 = tx3.getRawDataToSign(0);
        Signature sigObj3 = Signature.getInstance("SHA256withRSA");
        sigObj3.initSign(privateKey1);
        sigObj3.update(dataToSign3);
        byte[] signature3 = sigObj3.sign();
        tx3.addSignature(signature3, 0);
        tx3.finalize();
        System.out.println("Tx3 isValid (UTXO not in pool): " + handler3.isValidTx(tx3));

        // Test Case 4: UTXO claimed multiple times in the same transaction
        System.out.println("\n--- Test Case 4: UTXO claimed multiple times ---");
        TxHandler handler4 = new TxHandler(new UTXOPool(initialPool));
        Transaction tx4 = new Transaction();
        tx4.addInput(genesisTx.getHash(), 0);
        tx4.addInput(genesisTx.getHash(), 0);
        tx4.addOutput(1.0, publicKey2);
        tx4.addSignature(signature1, 0);
        tx4.addSignature(signature1, 1);
        tx4.finalize();
        System.out.println("Tx4 isValid (double claim same tx): " + handler4.isValidTx(tx4));

        // Test Case 5: Negative output value
        System.out.println("\n--- Test Case 5: Negative output value ---");
        TxHandler handler5 = new TxHandler(new UTXOPool(initialPool));
        Transaction tx5 = new Transaction();
        tx5.addInput(genesisTx.getHash(), 0);
        tx5.addOutput(-1.0, publicKey2);
        tx5.addSignature(signature1, 0);
        tx5.finalize();
        System.out.println("Tx5 isValid (negative output): " + handler5.isValidTx(tx5));

        // Test Case 6: Output sum exceeds input sum
        System.out.println("\n--- Test Case 6: Output sum > Input sum ---");
        TxHandler handler6 = new TxHandler(new UTXOPool(initialPool));
        Transaction tx6 = new Transaction();
        tx6.addInput(genesisTx.getHash(), 0);
        tx6.addOutput(11.0, publicKey2);
        tx6.addSignature(signature1, 0);
        tx6.finalize();
        System.out.println("Tx6 isValid (output > input): " + handler6.isValidTx(tx6));

        // Test Case 7: handleTxs with a double spend attempt
        System.out.println("\n--- Test Case 7: handleTxs - Double Spend ---");
        TxHandler handler7 = new TxHandler(new UTXOPool(initialPool));
        Transaction tx7_spend1 = new Transaction();
        tx7_spend1.addInput(genesisTx.getHash(), 0);
        tx7_spend1.addOutput(1.0, publicKey2);
        tx7_spend1.addSignature(signature1, 0);
        tx7_spend1.finalize();

        Transaction tx7_spend2 = new Transaction();
        tx7_spend2.addInput(genesisTx.getHash(), 0);
        tx7_spend2.addOutput(2.0, publicKey2);
        byte[] dataToSign7_2 = tx7_spend2.getRawDataToSign(0);
        Signature sigObj7_2 = Signature.getInstance("SHA256withRSA");
        sigObj7_2.initSign(privateKey1);
        sigObj7_2.update(dataToSign7_2);
        tx7_spend2.addSignature(sigObj7_2.sign(), 0);
        tx7_spend2.finalize();

        System.out.println("tx7_spend1 individually valid: " + new TxHandler(new UTXOPool(initialPool)).isValidTx(tx7_spend1));
        System.out.println("tx7_spend2 individually valid: " + new TxHandler(new UTXOPool(initialPool)).isValidTx(tx7_spend2));

        Transaction[] possibleTxs7 = {tx7_spend1, tx7_spend2};
        Transaction[] acceptedTxs7 = handler7.handleTxs(possibleTxs7);
        System.out.println("Accepted Txs for Test Case 7 (double spend): " + acceptedTxs7.length);
        if (acceptedTxs7.length == 1) {
             System.out.println("Accepted Tx Hash: " + Arrays.toString(acceptedTxs7[0].getHash()));
             System.out.println("Is it tx7_spend1? " + Arrays.equals(acceptedTxs7[0].getHash(), tx7_spend1.getHash()));
        }

        // Test Case 8: handleTxs with dependent transactions
        System.out.println("\n--- Test Case 8: handleTxs - Dependent Transactions ---");
        KeyPair keyPairAlice = pair1;
        KeyPair keyPairBob = pair2;

        Transaction realGenesisTx = new Transaction();
        realGenesisTx.addOutput(20.0, keyPairAlice.getPublic());
        realGenesisTx.finalize();
        UTXO aliceInitialUTXO = new UTXO(realGenesisTx.getHash(), 0);
        UTXOPool poolForTest8 = new UTXOPool();
        poolForTest8.addUTXO(aliceInitialUTXO, realGenesisTx.getOutput(0));

        TxHandler handlerForTest8 = new TxHandler(poolForTest8);

        Transaction txA_8 = new Transaction();
        txA_8.addInput(realGenesisTx.getHash(), 0);
        txA_8.addOutput(15.0, keyPairBob.getPublic());
        Signature sigA_8 = Signature.getInstance("SHA256withRSA");
        sigA_8.initSign(keyPairAlice.getPrivate());
        sigA_8.update(txA_8.getRawDataToSign(0));
        txA_8.addSignature(sigA_8.sign(), 0);
        txA_8.finalize();

        Transaction txB_8 = new Transaction();
        txB_8.addInput(txA_8.getHash(), 0);
        txB_8.addOutput(12.0, keyPairAlice.getPublic());
        Signature sigB_8 = Signature.getInstance("SHA256withRSA");
        sigB_8.initSign(keyPairBob.getPrivate());
        sigB_8.update(txB_8.getRawDataToSign(0));
        txB_8.addSignature(sigB_8.sign(), 0);
        txB_8.finalize();

        Transaction[] possibleTxs8 = {txB_8, txA_8};
        System.out.println("txA_8 hash: " + Arrays.toString(txA_8.getHash()));
        System.out.println("txB_8 input prev hash: " + Arrays.toString(txB_8.getInput(0).prevTxHash));

        Transaction[] acceptedTxs8 = handlerForTest8.handleTxs(possibleTxs8);
        System.out.println("Accepted Txs for Test Case 8 (dependent txs): " + acceptedTxs8.length);

        for(Transaction t : acceptedTxs8) {
            System.out.println("Accepted Tx Hash: " + Arrays.toString(t.getHash()));
        }
        UTXO utxoFromTxA_8 = new UTXO(txA_8.getHash(), 0); // Output created by TxA_8
        UTXO utxoFromTxB_8 = new UTXO(txB_8.getHash(), 0); // Output created by TxB_8

        System.out.println("Pool for Test 8 contains output from TxA_8 (spent by TxB_8): " + handlerForTest8.utxoPool.contains(utxoFromTxA_8)); // Expected: false
        System.out.println("Pool for Test 8 contains output from TxB_8: " + handlerForTest8.utxoPool.contains(utxoFromTxB_8)); // Expected: true
        if(handlerForTest8.utxoPool.contains(utxoFromTxB_8) && handlerForTest8.utxoPool.getTxOutput(utxoFromTxB_8) != null){
            System.out.println("Value of utxoFromTxB_8: " + handlerForTest8.utxoPool.getTxOutput(utxoFromTxB_8).value);
        }


        // Test Case 9: Transaction with no inputs
        System.out.println("\n--- Test Case 9: Transaction with no inputs ---");
        TxHandler handler9 = new TxHandler(new UTXOPool(initialPool));
        Transaction tx9_no_inputs = new Transaction();
        tx9_no_inputs.addOutput(5.0, publicKey1);
        tx9_no_inputs.finalize();
        System.out.println("Tx9 isValid (no inputs): " + handler9.isValidTx(tx9_no_inputs));

        System.out.println("\nAll tests complete.");
    }
    
}
