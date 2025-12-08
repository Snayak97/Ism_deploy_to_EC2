import React from "react";
import { AiFillInfoCircle } from "react-icons/ai";

const Transaction = () => {
  return (
    <div className="md:flex md:gap-x-5  md:justify-between sm:flex-start space-y-6 bg-whiten ">
      <div className="md:flex  md:gap-x-16 flex-col md:flex-row space-y-6 ">
        <div>
          <div className="flex items-center gap-x-1 text-gray-500 bg-">
            <h1 className="text-[20px] ">Total Portfolio Value</h1>
            <AiFillInfoCircle className="text-[20px]" />
          </div>
          <h1 className="text-md">₹112,322.24</h1>
        </div>

        <div>
          <div className="flex items-center gap-x-1 text-gray-500">
            <h1 className="text-[20px] ">Wallet Balances</h1>
            <AiFillInfoCircle className="text-[20px]" />
          </div>
          <div className="flex gap-7">
            <h1 className="text-md">
              ₹112,322.24{" "}
              <span className="bg-gray-200 text-gray-600 rounded-2xl text-[16px] p-1">
                BTC
              </span>
            </h1>
            <h1 className="text-md">
              ₹112,322.24{" "}
              <span className="bg-gray-200 text-gray-600 rounded-2xl text-[16px] p-1">
                INR
              </span>
            </h1>
          </div>
        </div>
      </div>
      <div className="md:flex md:flex-row md:items-center md:justify-around sm:float-start space-x-7 ">
        <button className="bg-blue-700 text-white rounded-lg p-2 w-28  text-center text-[20px] ">
          Deposit
        </button>
        <button className="bg-blue-700 text-white rounded-lg w-30 p-2   text-center text-[20px]">
          Withdraw
        </button>
      </div>
    </div>
  );
};

export default Transaction;
