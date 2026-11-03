// Only the newly issued, signed invitation's fixed lifetime can extend initial
// agent readiness. Restart never renews it; normal/update readiness stays 15 s.
export function startupBudget(config,now=Date.now()){
 const expires=config.initialPairingExpiresAt;if(expires===undefined)return 15000;
 if(config.role!=='agent'||!Number.isSafeInteger(expires)||expires>now+300000)throw Error('Invalid first pairing deadline');
 return expires<=now?15000:Math.max(15000,expires-now+15000);
}
