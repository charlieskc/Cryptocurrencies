import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

public class TxHandler {
	
	private UTXOPool utxoPool;
	private HashSet<UTXO> UTXODoubleSpentMap = new HashSet();

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {   	
        // IMPLEMENT THIS
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
        // IMPLEMENT THIS
    	double sumInput=0,sumOutput=0;
    	int i=0;
    	HashSet<UTXO> UTXOMap = new HashSet();
    	for (Transaction.Input input:tx.getInputs()){
    		UTXO ut = new UTXO(input.prevTxHash, input.outputIndex);	
    		if(!UTXOMap.contains(ut))
    			UTXOMap.add(ut);
    		else return false;
    		if(!utxoPool.contains(ut))
    			return false;
    		if(!Crypto.verifySignature(utxoPool.getTxOutput(ut).address, tx.getRawDataToSign(i), input.signature))
				return false;
    		sumInput+=utxoPool.getTxOutput(ut).value;
    		i++;
    	}  	
    	for (Transaction.Output output:tx.getOutputs()){
    		if(output.value < 0) return false;
    		sumOutput += output.value;
    	}
    	if(sumOutput > sumInput) return false;

		return true;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        // IMPLEMENT THIS
    	//Transaction[] txList = null;
    	
    	List<Transaction> txList = new ArrayList<Transaction>();
    	for(Transaction tx:possibleTxs){
    		/*
    		for(Transaction.Input in:tx.getInputs()){
    			UTXO ut = new UTXO(in.prevTxHash, in.outputIndex);
    				if(isValidTx(tx))
    					if(!UTXODoubleSpentMap.contains(ut))
    					return;
    		}
    		*/
    		if(isValidTx(tx)){
    			txList.add(tx);
    		
	    		for(Transaction.Input in:tx.getInputs()){
	    			UTXO ut = new UTXO(in.prevTxHash, in.outputIndex);
	    			utxoPool.removeUTXO(ut);
	    		}
    		}
    	
    	}
    	
    	return txList.toArray(new Transaction[txList.size()]);
    	
    }

    public static void main(String args[]){
    /*
    	Transaction tx = new Transaction();
    	Transaction.Output output = new Transaction.Output();
    	Transaction.Input input = new Transaction.Input();
    	
    	
    */
    
    }
    
}
