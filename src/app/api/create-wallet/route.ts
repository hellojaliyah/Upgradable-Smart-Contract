import { prisma } from "@/utils/db";
import { walletFactoryContract } from "@/utils/getContracts";
import { randomBytes } from "crypto";
import { NextRequest, NextResponse } from "next/server";

// Define an async function to handle POST requests
export async function POST(req: NextRequest) {
  try {
    // Parse the request body to get the list of signers
    const { signers }: { signers: string[] } = await req.json();

    // Generate a random salt, convert it to hexadecimal, and prepend "0x"
    const salt = "0x" + randomBytes(32).toString("hex");

    // Call the getAddress function from the wallet factory contract with the signers and salt
    // This computes the counterfactual address for the wallet without deploying it
    const walletAddress = await walletFactoryContract.getAddress(signers, salt);

    // Use Prisma client to create a new wallet in the database with the signers, salt, address, and isDeployed set to false
    const response = await prisma.wallet.create({
      data: {
        salt: salt,
        signers: signers.map((s) => s.toLowerCase()), // Convert all signer addresses to lowercase for consistency
        isDeployed: false,
        address: walletAddress,
      },
    });

    // Return the created wallet as a JSON response
    return NextResponse.json(response);
  } catch (error) {
    // Log any errors and return them as a JSON response
    console.error(error);
    return NextResponse.json({ error });
  }
}