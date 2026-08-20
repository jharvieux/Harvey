declare function chargeCard(): Promise<void>;

export async function collectPayment(): Promise<void> {
  try {
    await chargeCard();
  } catch (error) {
    console.error(error);
  }
}
