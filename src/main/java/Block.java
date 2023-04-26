/**
 * Author: Samson Zhang
 */

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;

public class Block {
    private int index;
    private Timestamp timestamp;
    @SerializedName("Tx ")
    private String data;
    @SerializedName("PrevHash")
    private String previousHash;
    private BigInteger nonce = BigInteger.ZERO;
    private int difficulty;

    /**
     * Constructor to create a new Block
     * @param index
     * @param timestamp
     * @param data
     * @param difficulty
     */
    public Block(int index, Timestamp timestamp, String data, int difficulty) {
        this.index = index;
        this.timestamp = timestamp;
        this.data = data;
        this.difficulty = difficulty;
    }

    /**
     * This method computes a hash of the concatenation of
     * the index, timestamp, data, previousHash, nonce, and difficulty.
     *
     * @return a String holding Hexadecimal characters
     */
    public String calculateHash() {
        String stringtoHash = "" + index + timestamp + data + previousHash + nonce + difficulty;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(stringtoHash.getBytes());
            //Convert from Byte to Hexdecimal characters
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error calculating hash: " + e.getMessage());
        }
    }

    // Code from stack overflow
    // https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
    // Returns a hex string given an array of bytes
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Performs a proof of work to find a hash with the required number of leading zeros.
     *
     * @return The hash that satisfies the proof of work condition (leading 0's)
     */
    public String proofOfWork() {
        String target = "0".repeat(difficulty);
        String hash = calculateHash();
        while (!hash.startsWith(target)) {
            nonce = nonce.add(BigInteger.ONE);
            hash = calculateHash();
        }
        return hash;
    }

    /**
     * Uses Gson to serialize the block to JSON format.
     * @return The JSON format of the Block as a String
     */
    @Override
    public String toString() {
        Gson gson = new GsonBuilder().setDateFormat("yyyy-MM-dd hh:mm:ss.S").create();
        String blockString = gson.toJson(this);
        return blockString;
    }

    /**
     * Getters and setters for private variables
     */
    public String getData() {
        return this.data;
    }

    public int getDifficulty() {
        return this.difficulty;
    }

    public int getIndex() {
        return this.index;
    }

    public BigInteger getNonce() {
        return this.nonce;
    }

    public String getPreviousHash() {
        return this.previousHash;
    }

    public Timestamp getTimestamp() {
        return this.timestamp;
    }

    public void setData(String data) {
        this.data = data;
    }

    public void setDifficulty(int difficulty) {
        this.difficulty = difficulty;
    }

    public void setIndex(int index) {
        this.index = index;
    }

    public void setPreviousHash(String previousHash) {
        this.previousHash = previousHash;
    }

    public void setTimestamp(Timestamp timestamp) {
        this.timestamp = timestamp;
    }
}
