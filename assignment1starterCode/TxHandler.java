import java.security.PublicKey;
import java.util.*;

public class TxHandler {

    private UTXOPool utxoPool;

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        this.utxoPool = utxoPool;
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool,
     * (2) the signatures on each input of {@code tx} are valid,
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     * values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        List<Transaction.Input> inputs = tx.getInputs();
        List<Transaction.Output> outputs = tx.getOutputs();
        Set<UTXO> claimedUtxos = new HashSet<>();
        double inputSum = 0;
        double outputSum = 0;
        for (int i = 0; i < tx.numInputs(); i++) {
            Transaction.Input input = tx.getInput(i);
            UTXO utxo = utxoFromInput(input);
            // Verify (1)
            if (!utxoPool.contains(utxo)) {
                return false;
            }
            // Verify (3)
            if (claimedUtxos.contains(utxo)) {
                return false;
            }
            claimedUtxos.add(utxo);

            Transaction.Output previousOutput = utxoPool.getTxOutput(utxo);
            inputSum += previousOutput.value;

            byte[] rawData = tx.getRawDataToSign(i);
            PublicKey publicKey = previousOutput.address;
            byte[] signature = input.signature;
            // Verify (2)
            if (!Crypto.verifySignature(publicKey, rawData, signature)) {
                return false;
            }
        }

        for (Transaction.Output output : outputs) {
            // Verify (4)
            if (output.value < 0) {
                return false;
            }
            outputSum += output.value;
        }

        // Verify (5)
        if (inputSum < outputSum) {
            return false;
        }

        return true;
    }

    private UTXO utxoFromInput(Transaction.Input input) {
        return new UTXO(input.prevTxHash, input.outputIndex);
    }

    private void processTx(Transaction tx) {
        byte[] txHash = tx.getHash();
        for (Transaction.Input input : tx.getInputs()) {
            UTXO utxo = utxoFromInput(input);
            this.utxoPool.removeUTXO(utxo);
        }
        for(int i = 0; i < tx.numOutputs(); i++) {
            UTXO utxo = new UTXO(txHash, i);
            Transaction.Output output = tx.getOutput(i);
            this.utxoPool.addUTXO(utxo, output);
        }
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        List<Transaction> acceptedTransactions = new LinkedList<>();
        for (Transaction tx : possibleTxs) {
            if (!isValidTx(tx)) {
                continue;
            }
            processTx(tx);
            acceptedTransactions.add(tx);
        }
        Transaction[] handledTransactions = new Transaction[acceptedTransactions.size()];
        return acceptedTransactions.toArray(handledTransactions);
    }

}
