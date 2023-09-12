import { prisma } from "@/utils/db";
import { isAddress } from "ethers/lib/utils";
import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const walletAddress = searchParams.get("walletAddress");

    // Check if walletAddress is provided
    if (!walletAddress) {
      throw new Error("Missing or invalid address");
    }

    // Validate if the provided address is a valid Ethereum address
    if (!isAddress(walletAddress)) {
      throw new Error("Invalid Ethereum address");
    }

    // Use prisma to find the first wallet that matches the provided address
    const wallet = await prisma.wallet.findFirst({
      where: {
        address: walletAddress,
      },
    });

    return NextResponse.json(wallet);
  } catch (error) {
    console.error(error);
    return NextResponse.json({ error });
  }
}