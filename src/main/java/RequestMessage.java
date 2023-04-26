/**
 * Author: Samson Zhang
 */

import java.math.BigInteger;

public class RequestMessage {
    private String clientID, clientPublicKey, data, signature;
    private int operation, difficulty;
    private BigInteger e, n;

    public RequestMessage(String clientID, String clientPublicKey, int operation, String data,
                          int difficulty, BigInteger e, BigInteger n, String signature) {
        this.setClientID(clientID);
        this.setClientPublicKey(clientPublicKey);
        this.setOperation(operation);
        this.setData(data);
        this.setDifficulty(difficulty);
        this.setE(e);
        this.setN(n);
        this.setSignature(signature);
    }

    public String getClientID() {
        return clientID;
    }

    public void setClientID(String clientID) {
        this.clientID = clientID;
    }

    public String getClientPublicKey() {
        return clientPublicKey;
    }

    public void setClientPublicKey(String clientPublicKey) {
        this.clientPublicKey = clientPublicKey;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public int getOperation() {
        return operation;
    }

    public void setOperation(int operation) {
        this.operation = operation;
    }

    public int getDifficulty() {
        return difficulty;
    }

    public void setDifficulty(int difficulty) {
        this.difficulty = difficulty;
    }

    public BigInteger getE() {
        return e;
    }

    public void setE(BigInteger e) {
        this.e = e;
    }

    public BigInteger getN() {
        return n;
    }

    public void setN(BigInteger n) {
        this.n = n;
    }
}
