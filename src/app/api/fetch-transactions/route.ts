// Import necessary libraries
import { prisma } from "@/utils/db";
import { isAddress } from "ethers/lib/utils";
import { NextRequest, NextResponse } from "next/server";
import { Transaction, TransactionSignature, Wallet } from "@prisma/client";

// Define a type for transactions with signatures
export type TransactionWithSignatures = Transaction & {
  signatures: TransactionSignature[];
  wallet: Wallet;
  pendingSigners: string[];
};

// Define an asynchronous GET function
export async function GET(req: NextRequest) {
  try {
    // Extract walletAddress from the search parameters
    const { searchParams } = new URL(req.url);
    const walletAddress = searchParams.get("walletAddress");

    // Throw an error if walletAddress is missing or invalid
    if (!walletAddress) {
      throw new Error("Missing or invalid wallet address");
    }

    // Validate the Ethereum address
    if (!isAddress(walletAddress)) {
      throw new Error("Invalid Ethereum address");
    }

    // Fetch all transactions associated with the walletAddress
    const transactions = await prisma.transaction.findMany({
      where: {
        wallet: {
          address: walletAddress,
        },
      },
      include: {
        signatures: true,
        wallet: true,
      },
      orderBy: {
        txHash: {
          sort: "asc",
          nulls: "first",
        },
      },
    });

    // Augment transactions with pendingSigners
    const augmentedTransactions: TransactionWithSignatures[] = transactions.map(
      (transaction) => {
        // Filter out signers who haven't completed a signature
        const pendingSigners = transaction.wallet.signers.filter(
          (signer) =>
            !transaction.signatures.find(
              (signature) => signature.signerAddress === signer
            )
        );

        // Return the transaction with pendingSigners
        return {
          ...transaction,
          pendingSigners,
        };
      }
    );

    // Return the transactions in JSON format
    return NextResponse.json({ transactions: augmentedTransactions });
  } catch (error) {
    console.error(error);
    return NextResponse.json({ error });
  }
}