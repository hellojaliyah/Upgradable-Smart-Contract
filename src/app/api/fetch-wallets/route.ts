import { prisma } from "@/utils/db";
import { isAddress } from "ethers/lib/utils";
import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  try {
    // Extract the search parameters from the request URL
    const { searchParams } = new URL(req.url);
    // Get the address from the search parameters
    const address = searchParams.get("address");

    // If the address is not provided, throw an error
    if (!address) {
      throw new Error("Missing or invalid address");
    }

    // If the address is not a valid Ethereum address, throw an error
    if (!isAddress(address)) {
      throw new Error("Invalid Ethereum address");
    }

    // Use Prisma to find all wallets where the given address is a signer
    // Also include a count of transactions for each wallet
    const wallets = await prisma.wallet.findMany({
      where: {
        signers: {
          has: address.toLowerCase(),
        },
      },
      include: {
        _count: {
          select: {
            transactions: true,
          },
        },
      },
    });

    // Return the wallets as a JSON response
    return NextResponse.json(wallets);
  } catch (error) {
    // Log any errors to the console and return them as a JSON response
    console.error(error);
    return NextResponse.json({ error });
  }
}