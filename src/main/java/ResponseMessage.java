/**
 * Author: Samson Zhang
 */

import java.math.BigInteger;

public class ResponseMessage {
    private int selection, size;
    private String chainHash;
    private double totalHashes;
    private int totalDiff;
    private BigInteger recentNonce;
    private int diff, hps;
    private String response;

    public ResponseMessage(){}

    public int getSelection() {
        return selection;
    }

    public void setSelection(int selection) {
        this.selection = selection;
    }

    public int getSize() {
        return size;
    }

    public void setSize(int size) {
        this.size = size;
    }

    public int getTotalDiff() {
        return totalDiff;
    }

    public void setTotalDiff(int totalDiff) {
        this.totalDiff = totalDiff;
    }

    public BigInteger getRecentNonce() {
        return recentNonce;
    }

    public void setRecentNonce(BigInteger recentNonce) {
        this.recentNonce = recentNonce;
    }

    public int getDiff() {
        return diff;
    }

    public void setDiff(int diff) {
        this.diff = diff;
    }

    public int getHps() {
        return hps;
    }

    public void setHps(int hps) {
        this.hps = hps;
    }

    public double getTotalHashes() {
        return totalHashes;
    }

    public void setTotalHashes(double totalHashes) {
        this.totalHashes = totalHashes;
    }

    public String getChainHash() {
        return chainHash;
    }

    public void setChainHash(String chainHash) {
        this.chainHash = chainHash;
    }

    public String getResponse() {
        return response;
    }

    public void setResponse(String response) {
        this.response = response;
    }
}
