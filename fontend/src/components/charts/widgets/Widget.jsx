import React from "react";
import {
  FaUserAlt,
  FaShoppingCart,
  FaWallet,
  FaMoneyBillWave,
  FaArrowUp,
} from "react-icons/fa";

const Widget = ({ type }) => {
  let data;
  const amount = 100;
  const diff = 20;

  switch (type) {
    case "user":
      data = {
        title: "USERS",
        isMoney: false,
        link: "See all users",
        icon: (
          <FaUserAlt
            className="text-red-600 bg-red-200 p-1 rounded"
            size={24}
          />
        ),
      };
      break;
    case "order":
      data = {
        title: "ORDERS",
        isMoney: false,
        link: "View all orders",
        icon: (
          <FaShoppingCart
            className="text-yellow-600 bg-yellow-200 p-1 rounded"
            size={24}
          />
        ),
      };
      break;
    case "earning":
      data = {
        title: "EARNINGS",
        isMoney: true,
        link: "View net earnings",
        icon: (
          <FaMoneyBillWave
            className="text-green-600 bg-green-200 p-1 rounded"
            size={24}
          />
        ),
      };
      break;
    case "balance":
      data = {
        title: "BALANCE",
        isMoney: true,
        link: "See details",
        icon: (
          <FaWallet
            className="text-purple-600 bg-purple-200 p-1 rounded"
            size={24}
          />
        ),
      };
      break;
    default:
      data = {
        title: "UNKNOWN",
        isMoney: false,
        link: "No link available",
        icon: <></>,
      };
  }

  return (
    <div className="flex flex-1 justify-between p-4 shadow-md rounded-lg h-24 md:h-28 bg-white dark:bg-neutral-900 dark:text-white dark:border-1 dark:border-transparent dark:hover:border-gray-300 dark:hover:shadow-[0_0_10px_2px_rgba(255,255,255,0.7)] transition-all duration-300 hover:scale-102 transform  ease-in-out">
      <div className="flex flex-col justify-between">
        <span className="text-sm md:text-base font-semibold text-gray-500 dark:text-gray-400">
          {data.title}
        </span>
        <span className="text-2xl md:text-3xl font-light">
          {data.isMoney && "$"} {amount}
        </span>
        <span className="text-xs md:text-sm border-b border-gray-400 w-max cursor-pointer text-gray-600 dark:text-gray-300">
          {data.link}
        </span>
      </div>

      <div className="flex flex-col justify-between items-end">
        <div className="flex items-center text-green-600 text-sm md:text-base font-semibold">
          <FaArrowUp className="mr-1" />
          {diff} %
        </div>
        {data.icon}
      </div>
    </div>
  );
};

export default Widget;
