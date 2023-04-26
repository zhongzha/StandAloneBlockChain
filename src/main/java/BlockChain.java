/**
 * Author: Samson Zhang
 */

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.util.ArrayList;

public class BlockChain {
    private ArrayList<Block> blockChain;
    private String chainHash;
    private int hashPerSecond;

    /**
     * Constructor to create a new BlockChain
     */
    public BlockChain() {
        blockChain = new ArrayList<>();
        chainHash = new String();
        hashPerSecond = 0;
    }

    /**
     * Adds a new block to the blockchain.
     *
     * @param newBlock The block to add to the blockchain.
     *
     * Time complexity: The run time of addBlock() can vary depending on the size of the existing blockchain
     *                and the difficulty level of the proof of work algorithm.
     */
    public void addBlock(Block newBlock) {
        // If the blockchain is empty,
        // set the previous hash of the new block to an empty string.
        if (blockChain.isEmpty()) {
            newBlock.setPreviousHash("");
        } else {
            //set the previous hash of the new block to the hash of the last block in the chain.
            newBlock.setPreviousHash(chainHash);
        }
        // Calculate the proof of work
        this.chainHash = newBlock.proofOfWork();
        blockChain.add(newBlock);
    }


    /**
     * This method computes exactly 2 million hashes and times how long that process takes.
     */
    public void computeHashesPerSecond() {
        int num = 2_000_000;
        long startTime = System.nanoTime();
        for (int i = 0; i < num; i++) {
            hash("00000000");
        }
        long endTime = System.nanoTime();

        double elapsedTimeSeconds = (endTime - startTime) / 1_000_000_000.0;

        hashPerSecond = (int) (num / elapsedTimeSeconds);
    }

    /**
     * This method computes a hash of a given string
     *
     * @return a String holding Hexadecimal characters
     */
    private String hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes());

            return Block.bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error calculating hash: " + e.getMessage());
        }
    }

    /**
     * Compute and return the total difficulty of all blocks on the chain.
     * @return totalDifficulty
     */
    public int getTotalDifficulty() {
        int totalDifficulty = 0;
        for (int i = 0; i < blockChain.size(); i++) {
            totalDifficulty += blockChain.get(i).getDifficulty();
        }
        return totalDifficulty;
    }

    /**
     * Compute and return the expected number of hashes required for the entire chain.
     *
     * @return totalExpectedHashes
     */
    public double getTotalExpectedHashes() {
        double totalExpectedHashes = 0;
        for (int i = 0; i <  blockChain.size(); i++) {
            totalExpectedHashes += Math.pow(16, blockChain.get(i).getDifficulty());
        }
        return totalExpectedHashes;
    }

    /**
     * If the chain only contains one block, the genesis block at position 0,
     * this routine computes the hash of the block and checks that the hash has the requisite number of leftmost 0's
     * (proof of work) as specified in the difficulty field.
     *
     * Time Complexity: O(N)
     *
     * @return String that describe the validity of the entire chain
     */
    public String isChainValid() {
        Block genesisBlock;
        if (blockChain.size() == 1) {
            genesisBlock = blockChain.get(0);
            String genesisHash = genesisBlock.calculateHash();
            int difficulty = genesisBlock.getDifficulty();
            if (!genesisHash.startsWith("0".repeat(difficulty))) {
                return "FALSE\nInvalid proof of work for the genesis block";
            }
            if (!genesisHash.equals(chainHash)) {
                return "FALSE\nInvalid chain hash for the genesis block";
            }
            return "TRUE";
        }

        Block previousBlock = blockChain.get(0);
        for (int i = 1; i < blockChain.size(); i++) {
            Block currentBlock = blockChain.get(i);
            if (!currentBlock.getPreviousHash().equals(previousBlock.calculateHash())) {
                return "FALSE\nInvalid previous hash for block " + i;
            }
            int difficulty = currentBlock.getDifficulty();
            String currentHash = currentBlock.calculateHash();
            if (!currentHash.startsWith("0".repeat(difficulty))) {
                return String.format("FALSE\nImproper hash on node %s Does not begin with %s", i, "0".repeat(difficulty));
            }
            previousBlock = currentBlock;
        }
        if (!previousBlock.proofOfWork().equals(chainHash)) {
            return "FALSE\nInvalid chain hash";
        }
        return "TRUE";
    }

    /**
     * check proof of work for each block
     * check previous == current
     * set chainHash to the latest block hash
     *
     * Time Complexity: O(N)
     */
    public void repairChain() {
        Block previousBlock = null;
        for (int i = 1; i < blockChain.size(); i++) {
            Block currentBlock = blockChain.get(i);
            int difficulty = currentBlock.getDifficulty();
            String currentHash = currentBlock.calculateHash();
            if (!currentHash.startsWith("0".repeat(difficulty))) {
                currentBlock.proofOfWork();
            }
            String previousHash = blockChain.get(i - 1).proofOfWork();
            if (previousBlock != null && !currentBlock.getPreviousHash().equals(previousHash)) {
                currentBlock.setPreviousHash(previousHash);
            }
            previousBlock = currentBlock;
        }

        if (blockChain.size() != 1) {
            chainHash = previousBlock.proofOfWork();
        }
    }

    /**
     * JSON format of the Chain as String
     * @return BlockChain String
     */
    @Override
    public String toString() {
        String pre = "{\"ds_chain\" : ";
        String end = String.format("], \"chainHash\":\"%s\"}", chainHash);

        StringBuilder bcString = new StringBuilder();
        for (Block b : blockChain) {
            bcString.append(b.toString() + "\n");
        }

        return pre + bcString + end;
    }

    /**
     * Getters and setters for private variables
     */
    public Block getBlock(int i) {
        return blockChain.get(i);
    }

    public String getChainHash() {
        return chainHash;
    }

    public int getChainSize() {
        return blockChain.size();
    }

    public int getHashesPerSecond() {
        return hashPerSecond;
    }

    public Block getLatestBlock() {
        return blockChain.get(blockChain.size() - 1);
    }

    public Timestamp getTime() {
        return new Timestamp(System.currentTimeMillis());
    }

}
