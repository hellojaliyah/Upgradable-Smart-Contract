// Import necessary libraries
import { prisma } from "@/utils/db";
import { NextRequest, NextResponse } from "next/server";

// Define an asynchronous POST function
export async function POST(req: NextRequest) {
  try {
    // Destructure signature, signerAddress, and transactionId from the request
    const { signature, signerAddress, transactionId } = await req.json();

    // Update the transaction with the new signature
    await prisma.transaction.update({
      where: {
        id: transactionId,
      },
      data: {
        signatures: {
          create: {
            signature,
            signerAddress: signerAddress.toLowerCase(),
          },
        },
      },
    });

    // Return a success message
    return NextResponse.json({ success: true });
  } catch (error) {
    console.error(error);
    return NextResponse.json({ error });
  }
}