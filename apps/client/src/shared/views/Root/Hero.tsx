import styles from "../../../utils/styles";
import { Button } from "@nextui-org/button";

const Hero = () => {
  return (
    <div className="w-full h-[92vh] banner flex items-center z-10 absolute">
      <div className="backdrop_shaders w-full" />
      <div className="w-[80%] m-auto">
        <h1 className="text-4xl py-5 xl:text-6xl font-[700] xl:leading-[80px] sm:mt-20 font-Inter">
          Fresh and Stunning Foods
          <br />
          Available for Delivery
        </h1>
        <p className={`${styles.label} !text-[18px]`}>
          Order your favorite meals and get them in less than 30 minutes.
          <br /> We offer the best food delivery service in town.
        </p>
        <br />
        <Button className={`${styles.button} w-[180px] md:mb-12`}>
          INN Order Now
        </Button>
      </div>
    </div>
  );
};

export default Hero;
