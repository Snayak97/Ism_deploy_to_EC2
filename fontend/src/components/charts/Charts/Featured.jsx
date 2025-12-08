import React from "react";
import { CircularProgressbar } from "react-circular-progressbar";
import "react-circular-progressbar/dist/styles.css";
import { FiMoreVertical, FiArrowDown, FiArrowUp } from "react-icons/fi";

const Featured = () => {
  return (
    <div className="flex-1 p-4 sm:p-6 shadow-md rounded-xl bg-white dark:bg-neutral-900 dark:text-white hover:scale-102 transition transform duration-300 ease-in-out dark:hover:border-gray-300 dark:hover:shadow-[0_0_10px_2px_rgba(255,255,255,0.7)] dark:border-1 dark:border-transparent">
      {/* Top */}
      <div className="flex items-center justify-between text-gray-500 dark:text-gray-300">
        <h1 className="text-base sm:text-lg font-medium">Total Revenue</h1>
        <FiMoreVertical size={20} />
      </div>

      {/* Bottom */}
      <div className="flex flex-col items-center justify-center gap-4 mt-6">
        <div className="w-20 h-20 sm:w-24 sm:h-24">
          <CircularProgressbar value={70} text={"70%"} strokeWidth={5} />
        </div>

        <p className="text-gray-500 dark:text-gray-400 font-medium text-sm sm:text-base">
          Total sales made today
        </p>
        <p className="text-2xl sm:text-4xl font-light text-black dark:text-white">$420</p>
        <p className="text-xs sm:text-sm text-center text-gray-500 dark:text-gray-400 font-light max-w-xs sm:max-w-md">
          Previous transactions processing. Last payments may not be included.
        </p>

        {/* Summary */}
        <div className="w-full flex flex-col sm:flex-row justify-between gap-4 mt-6">
          {/* Target */}
          <div className="text-center w-full sm:w-auto">
            <div className="text-sm sm:text-base text-gray-500 dark:text-gray-400">
              Target
            </div>
            <div className="flex justify-center items-center gap-1 mt-2 text-red-500 text-sm sm:text-base">
              <FiArrowDown size={16} />
              <div>$12.4k</div>
            </div>
          </div>

          {/* Last Week */}
          <div className="text-center w-full sm:w-auto">
            <div className="text-sm sm:text-base text-gray-500 dark:text-gray-400">
              Last Week
            </div>
            <div className="flex justify-center items-center gap-1 mt-2 text-green-600 text-sm sm:text-base">
              <FiArrowUp size={16} />
              <div>$12.4k</div>
            </div>
          </div>

          {/* Last Month */}
          <div className="text-center w-full sm:w-auto">
            <div className="text-sm sm:text-base text-gray-500 dark:text-gray-400">
              Last Month
            </div>
            <div className="flex justify-center items-center gap-1 mt-2 text-green-600 text-sm sm:text-base">
              <FiArrowUp size={16} />
              <div>$12.4k</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Featured;
